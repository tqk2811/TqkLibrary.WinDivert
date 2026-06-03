using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.WinDivert.Pipeline;

namespace TqkLibrary.WinDivert.Redirect;

[Flags]
public enum RedirectProtocol
{
    None = 0,
    Tcp = 1,
    Udp = 2,
    All = Tcp | Udp,
}

public delegate Task TcpConnectionHandler(RedirectedTcpConnection connection, CancellationToken ct);

// Called for each outbound UDP datagram. Return the (possibly rewritten) payload to forward
// to the original destination, or null to drop. Incoming replies are delivered to the process
// unchanged; to modify replies, set ReplyHandler.
public delegate byte[]? UdpDatagramHandler(RedirectedUdpDatagram datagram, CancellationToken ct);

public sealed class RedirectOptions
{
    public uint ProcessId { get; set; }
    public RedirectProtocol Protocols { get; set; } = RedirectProtocol.Tcp;

    // If null, RedirectedTcpConnection.RelayAsync() is called for a default pass-through pipe.
    public TcpConnectionHandler? TcpConnectionHandler { get; set; }

    // If null, UDP datagrams are forwarded unchanged.
    public UdpDatagramHandler? UdpDatagramHandler { get; set; }

    // Applied to the WinDivert NETWORK handle priority (-30000..30000; higher = earlier).
    public short NetworkPriority { get; set; } = 100;
    public short SocketPriority { get; set; } = 100;

    // If set, every captured packet, redirect, NAT entry, and socket event is appended to this
    // file with a UTC timestamp. Null disables diagnostic logging (no overhead).
    public string? LogFilePath { get; set; }

    // When true, opens a parallel WinDivert handle that drops IPv6 TCP/UDP traffic belonging
    // to the target process. The interceptor itself is IPv4-only, so without this any AAAA-
    // resolved connection would emit through the kernel direct and leak the real IPv6 address.
    // Non-target IPv6 traffic is re-injected unchanged.
    public bool BlockIpv6 { get; set; } = true;

    // If null or empty, every destination port of the tracked process is NAT-redirected to the
    // local relay (current default). When set, only outbound packets whose destination port is
    // in this collection are redirected; other ports pass through the kernel unchanged and
    // reach the original destination directly — they DO NOT go through the proxy and DO NOT
    // get IP-leak protection. Applies to whatever protocols are enabled via Protocols.
    public IReadOnlyCollection<ushort>? RedirectDestinationPorts { get; set; }

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
}
