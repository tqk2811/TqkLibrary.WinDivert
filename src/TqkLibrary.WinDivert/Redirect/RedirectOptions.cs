using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TqkLibrary.WinDivert.Pipeline;

namespace TqkLibrary.WinDivert.Redirect;

public sealed class RedirectOptions
{
    public uint ProcessId { get; set; }
    public RedirectProtocol Protocols { get; set; } = RedirectProtocol.Tcp;

    // If null, RedirectedTcpConnection.RelayDirectAsync() is called: the relay opens a socket to
    // the original destination and pipes verbatim. Set a handler to route the connection somewhere
    // else (upstream proxy, VPN, block) — nothing is connected until the handler asks for it.
    public TcpConnectionHandler? TcpConnectionHandler { get; set; }

    // If null, UDP datagrams are forwarded unchanged.
    public UdpDatagramHandler? UdpDatagramHandler { get; set; }

    // Applied to the WinDivert NETWORK handle priority (-30000..30000; higher = earlier).
    public short NetworkPriority { get; set; } = 100;

    // Applied to the per-process WinDivert SOCKET handles. These are sniffing handles, so the
    // priority only decides the order relative to other WinDivert clients; 0 keeps this tracker
    // out of the way of anything the user runs alongside it.
    public short SocketPriority { get; set; } = 0;

    // If set, every captured packet, redirect, NAT entry, and socket event is appended to this
    // file with a UTC timestamp. Null disables file logging. Ignored when Logger is set.
    public string? LogFilePath { get; set; }

    // Host logging for the same stream. Ignored when Logger is set; not disposed by the redirector.
    public ILoggerFactory? LoggerFactory { get; set; }

    // A logger built by the caller — use this to subscribe to RedirectLogger.EntryWritten (e.g. a
    // UI log pane) or to share one sink across several redirectors. When set, LogFilePath and
    // LoggerFactory are not used and the redirector does NOT dispose the logger.
    public RedirectLogger? Logger { get; set; }

    // What happens to the target's IPv6 traffic. Redirect (default) opens a parallel IPv6 NETWORK
    // handle running the same NAT pipeline as IPv4, so IPv6 connections reach the relay and the
    // connection handler just like IPv4 ones. Block keeps the old behaviour (drop the target's
    // IPv6 so the application falls back to IPv4); Ignore lets it out untouched. Either way
    // non-target IPv6 traffic is re-injected unchanged.
    public Ipv6Mode Ipv6Mode { get; set; } = Ipv6Mode.Redirect;

    // If null or empty, every destination port of the tracked process is NAT-redirected to the
    // local relay (current default). When set, only outbound packets whose destination port is
    // in this collection are redirected; other ports pass through the kernel unchanged and
    // reach the original destination directly — they DO NOT go through the proxy and DO NOT
    // get IP-leak protection. Applies to whatever protocols are enabled via Protocols.
    public IReadOnlyCollection<ushort>? RedirectDestinationPorts { get; set; }

    // What to do with a TCP flow whose handshake began before the redirector could claim it
    // (a process attached while it already had sockets open, or the SOCKET event losing the race
    // against the SYN).
    //
    // false (default): let it through. The connection keeps working, but its packets reach the
    //   destination directly, so the real IP is exposed for that one connection.
    // true: drop it. Nothing leaks; the application sees the connection fail and opens a new one,
    //   which is captured properly from its SYN. Note this also kills every connection a process
    //   already had open at the moment it was attached.
    //
    // Either way the flow is NEVER redirected mid-stream: half a connection going direct and half
    // through the relay breaks it outright.
    public bool BlockEscapedFlows { get; set; } = false;

    // Hook to insert custom packet middlewares into the IPv4 NETWORK pipeline. Invoked after the
    // built-in NatRedirectMiddleware is registered, so user middlewares run on packets the NAT
    // stage did not claim (its egress/reply legs short-circuit before reaching them). Use this to
    // observe, rewrite, or block specific traffic. The pipeline is ASP.NET-style: call next() to
    // defer, or set a disposition (Drop/MarkModified) and return to terminate.
    public Action<PacketPipelineBuilder>? ConfigureNetworkPipeline { get; set; }

    // When true, a background task periodically reads the Windows DNS Client Service cache
    // (`ipconfig /displaydns`) so log lines and console events can annotate destination IPs
    // with their resolved domain names. Names accumulate within the redirector's lifetime, so
    // a name once seen for an IP keeps resolving even after the OS DNS cache evicts it.
    public bool EnableDnsLookup { get; set; } = true;

    // When true, DNS answers seen on the wire (UDP source port 53) are parsed and their
    // IP -> domain mappings kept in ProcessRedirector.ReverseDns. This is what makes domain-based
    // routing possible for connections that expose no name of their own (no SNI, no Host header),
    // and it works even when the lookup was made by the Windows resolver service rather than by
    // the target process. Implies capturing UDP on the NETWORK handle.
    //
    // With EnableSecureDns the classic answers never appear, but the DoH answers feed the same
    // table, so domain routing keeps working either way.
    public bool EnableDnsSniff { get; set; } = true;

    // When true, the target's outbound IPv4 UDP/53 (classic DNS) is intercepted and resolved over
    // HTTPS (DoH) instead of being forwarded; the answer is injected back to the process. Lets DNS
    // keep working when the proxy can't tunnel UDP. DNS/53 then never reaches the UDP relay or
    // UdpDatagramHandler. See DohEndpoint.
    public bool EnableSecureDns { get; set; } = false;

    // DoH endpoint used when EnableSecureDns is true. Default Cloudflare via IP literal (avoids a
    // bootstrap DNS lookup for the resolver's own hostname; its cert has an IP SAN).
    public Uri DohEndpoint { get; set; } = new Uri("https://1.1.1.1/dns-query");

    // When true, the target's outbound IPv4 UDP not claimed by an earlier middleware (e.g. not
    // DNS-over-HTTPS) is dropped rather than NAT-redirected/passed. Use this when the proxy cannot
    // carry UDP and UDP must not leak out direct. Combined with EnableSecureDns this yields
    // "block all of the target's UDP except DNS, which is served over DoH".
    public bool BlockUnhandledTargetUdp { get; set; } = false;
}
