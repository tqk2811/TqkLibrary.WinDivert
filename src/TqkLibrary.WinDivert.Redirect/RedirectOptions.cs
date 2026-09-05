using System;
using System.Collections.Generic;

namespace TqkLibrary.WinDivert.Redirect;

/// <summary>
/// Everything one redirect session needs to know. Passed to
/// <see cref="Interfaces.IProcessRedirectorFactory.Create"/>; the redirector reads it once at
/// Start and does not watch it for changes afterwards.
/// </summary>
/// <remarks>
/// There is deliberately nothing about logging here: every component logs through
/// <c>ILogger&lt;T&gt;</c>, so where the lines go is the host's decision, made once when it builds
/// its logging, not a per-session setting.
/// </remarks>
public sealed class RedirectOptions
{
    /// <summary>
    /// Root process to capture. Zero starts with an empty scope, for a host that feeds pids in
    /// through <see cref="Interfaces.IProcessRedirector.AddTrackedProcessId"/> as its own watcher
    /// discovers them.
    /// </summary>
    public uint ProcessId { get; set; }

    public RedirectProtocol Protocols { get; set; } = RedirectProtocol.Tcp;

    /// <summary>
    /// Decides where each redirected TCP connection really goes. Null means
    /// <see cref="Models.RedirectedTcpConnection.RelayDirectAsync"/>: the relay opens a socket to
    /// the original destination and pipes verbatim. Nothing is connected until the handler asks
    /// for it, so a handler is free to route, rewrite, or refuse.
    /// </summary>
    public TcpConnectionHandler? TcpConnectionHandler { get; set; }

    /// <summary>Null forwards UDP datagrams unchanged.</summary>
    public UdpDatagramHandler? UdpDatagramHandler { get; set; }

    /// <summary>
    /// Consulted before a tracked UDP flow is redirected. Returning false leaves the datagram
    /// completely untouched — it reaches the original destination from the process's own socket,
    /// so the reply comes straight back and the flow carries the machine's real address. Null
    /// (the default) redirects every UDP flow.
    /// </summary>
    /// <remarks>
    /// Only UDP has this hook, and only because the UDP relay cannot deliver a direct route: it
    /// forwards from its own socket, on a port the NAT table has no entry for, so nothing can
    /// route the reply back to the process. TCP needs no equivalent — the relay owns both ends of
    /// a stream socket — and a TCP flow must not be diverted at packet level anyway, since the
    /// name it is routed by only appears after the handshake.
    /// </remarks>
    public UdpRedirectPredicate? ShouldRedirectUdp { get; set; }

    /// <summary>WinDivert NETWORK handle priority (-30000..30000; higher runs earlier).</summary>
    public short NetworkPriority { get; set; } = 100;

    /// <summary>
    /// Priority of the per-process SOCKET handles. These only sniff, so the number just orders
    /// this tracker against other WinDivert clients; 0 keeps it out of the way of anything else
    /// the user is running.
    /// </summary>
    public short SocketPriority { get; set; } = 0;

    /// <summary>
    /// What happens to the target's IPv6 traffic. Redirect (default) opens a parallel IPv6 NETWORK
    /// handle running the same NAT pipeline as IPv4, so IPv6 connections reach the relay and the
    /// connection handler just like IPv4 ones. Block drops the target's IPv6 so the application
    /// falls back to IPv4; Ignore lets it out untouched. Either way, IPv6 belonging to other
    /// processes is re-injected unchanged.
    /// </summary>
    public Ipv6Mode Ipv6Mode { get; set; } = Ipv6Mode.Redirect;

    /// <summary>
    /// Null or empty redirects every destination port of the tracked processes. When set, only
    /// outbound packets whose destination port is in this collection are redirected; the others
    /// pass through the kernel unchanged and reach the original destination directly — so they DO
    /// NOT go through the proxy and DO NOT get IP-leak protection. Applies to whichever protocols
    /// <see cref="Protocols"/> enables.
    /// </summary>
    public IReadOnlyCollection<ushort>? RedirectDestinationPorts { get; set; }

    /// <summary>
    /// What to do with a TCP flow whose handshake began before the redirector could claim it — a
    /// process attached while it already had sockets open, or the SOCKET event losing the race
    /// against the SYN.
    /// </summary>
    /// <remarks>
    /// false (default): let it through. The connection keeps working, but its packets reach the
    /// destination directly, so the real IP is exposed for that one connection.
    /// true: drop it. Nothing leaks; the application sees the connection fail and opens a new one,
    /// which is captured properly from its SYN — but this also kills every connection a process
    /// already had open at the moment it was attached.
    ///
    /// Either way the flow is NEVER redirected mid-stream: half a connection going direct and half
    /// through the relay breaks it outright.
    /// </remarks>
    public bool BlockEscapedFlows { get; set; } = false;

    /// <summary>
    /// Hook for inserting custom middlewares into a NETWORK pipeline. Invoked once per address
    /// family, after the built-in NAT stage is registered — so user middlewares see the packets
    /// NAT did not claim, and a callback that news up its middleware gets one instance per
    /// pipeline and never has to be thread-safe across the two pump threads.
    /// </summary>
    public Action<PacketPipelineBuilder>? ConfigureNetworkPipeline { get; set; }

    /// <summary>
    /// When true, a background task periodically reads the Windows DNS client cache so log lines
    /// and UI rows can annotate destination IPs with their names. Names accumulate for the life of
    /// the redirector, so one seen for an IP keeps resolving even after the OS cache evicts it.
    /// </summary>
    public bool EnableDnsLookup { get; set; } = true;

    /// <summary>
    /// When true, DNS answers seen on the wire (UDP source port 53) are parsed and their
    /// IP to domain mappings kept in <see cref="Interfaces.IProcessRedirector.ReverseDns"/>. This
    /// is what makes domain-based routing possible for connections that expose no name of their
    /// own (no SNI, no Host header), and it works even when the lookup was made by the Windows
    /// resolver service rather than by the target process. Implies capturing UDP on the NETWORK
    /// handle.
    /// </summary>
    /// <remarks>
    /// With <see cref="EnableSecureDns"/> the classic answers never appear, but the DoH answers
    /// feed the same table, so domain routing keeps working either way.
    /// </remarks>
    public bool EnableDnsSniff { get; set; } = true;

    /// <summary>
    /// When true, the target's outbound IPv4 UDP/53 is intercepted and resolved over HTTPS instead
    /// of being forwarded, and the answer is injected back to the process. This is what lets DNS
    /// keep working when the proxy cannot tunnel UDP. DNS/53 then never reaches the UDP relay or
    /// the <see cref="UdpDatagramHandler"/>.
    /// </summary>
    public bool EnableSecureDns { get; set; } = false;

    /// <summary>
    /// DoH endpoint used when <see cref="EnableSecureDns"/> is on. Null uses the library default,
    /// an IP literal — which avoids a bootstrap DNS lookup for the resolver's own hostname.
    /// </summary>
    public Uri? DohEndpoint { get; set; }

    /// <summary>
    /// When true, the target's outbound UDP that no earlier middleware claimed is dropped rather
    /// than redirected or passed. Use it when the proxy cannot carry UDP and UDP must not leak out
    /// direct; combined with <see cref="EnableSecureDns"/> it yields "block all of the target's
    /// UDP except DNS, which is served over DoH".
    /// </summary>
    public bool BlockUnhandledTargetUdp { get; set; } = false;
}
