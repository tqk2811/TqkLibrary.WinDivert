using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace TqkLibrary.WinDivert.Redirect;

/// <summary>
/// The NAT stage: rewrites the target process's outbound packets onto the local relay, and the
/// relay's replies back onto the original addresses. Packets it does not claim are deferred to the
/// rest of the chain, so it must run first in its pipeline.
/// </summary>
/// <remarks>
/// One instance serves one address family — registered once in the IPv4 pipeline and once in the
/// IPv6 one, each carrying that family's relay ports.
///
/// Outbound (target process to the real destination):
///   (srcA:sp, dstB:bp) becomes (loopback:sp, loopback:relayPort), and the table records
///   sp -> { origSrc=A, origDst=B:bp, pid }.
///
/// Inbound on loopback (relay back to the target process):
///   (loopback:relayPort, loopback:sp) becomes (B:bp, A:sp), found by dstPort=sp.
/// </remarks>
public sealed class NatRedirectMiddleware : IPacketMiddleware
{
    private readonly INatTable _nat;
    private readonly ISocketTracker _tracker;
    private readonly IDnsCacheLookup? _dnsLookup;
    private readonly ILogger<NatRedirectMiddleware> _logger;

    private readonly RelayPorts _relayPorts;

    // Which protocols this stage NAT-redirects. The handle filter may capture more (UDP for a
    // downstream DNS or block middleware, say); packets of a protocol not in this set are deferred
    // via next() so NAT never touches them.
    private readonly RedirectProtocol _protocols;

    // null = redirect every destination port; non-null = whitelist (only these are redirected, the
    // rest pass through to their real destination).
    private readonly HashSet<ushort>? _dstPortFilter;

    // What to do with a TCP flow whose handshake started before this stage could claim it — see
    // HandleEscapedFlow.
    private readonly bool _blockEscapedFlows;

    // The redirector's ROOT pid, used only as a fallback when the flow lookup misses. A redirector
    // can follow many pids, so the owner of the packet in hand comes from the tracker.
    private readonly uint _rootProcessId;

    public NatRedirectMiddleware(
        INatTable nat,
        ISocketTracker tracker,
        RelayPorts relayPorts,
        RedirectProtocol protocols,
        uint rootProcessId,
        ILogger<NatRedirectMiddleware> logger,
        IDnsCacheLookup? dnsLookup = null,
        IReadOnlyCollection<ushort>? destinationPortFilter = null,
        bool blockEscapedFlows = false)
    {
        _nat = nat ?? throw new ArgumentNullException(nameof(nat));
        _tracker = tracker ?? throw new ArgumentNullException(nameof(tracker));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _dnsLookup = dnsLookup;
        _relayPorts = relayPorts;
        _protocols = protocols;
        _rootProcessId = rootProcessId;
        _blockEscapedFlows = blockEscapedFlows;
        _dstPortFilter = (destinationPortFilter != null && destinationPortFilter.Count > 0)
            ? new HashSet<ushort>(destinationPortFilter)
            : null;
    }

    public Task InvokeAsync(PacketContext ctx, PacketDelegate next)
    {
        ParsedPacket? p = ctx.Packet;
        if (p == null || !(p.IsTcp || p.IsUdp))
            return next(ctx);

        bool isTcp = p.IsTcp;
        // Only NAT the protocols we were asked to; defer the rest to downstream middlewares.
        RedirectProtocol thisProto = isTcp ? RedirectProtocol.Tcp : RedirectProtocol.Udp;
        if ((_protocols & thisProto) == 0)
            return next(ctx);

        byte proto = (byte)p.Protocol;
        bool isIpv6 = p.IsIpv6;
        int expectedRelay = _relayPorts.For(isTcp, isIpv6);
        // No relay socket for this family: nothing here can redirect the packet, so let the rest
        // of the chain (block/observe middlewares) decide what happens to it.
        if (expectedRelay == 0)
            return next(ctx);

        if (_logger.IsEnabled(LogLevel.Trace))
            _logger.LogTrace("recv {Packet}", Describe(p, ctx.Address, ctx.Length));

        // Case 1: egress from target process on a real interface -> redirect to local relay.
        if (ctx.Address.Outbound && !ctx.Address.Loopback)
            return HandleEgress(ctx, next, p, proto, isTcp, isIpv6, expectedRelay);

        // Case 2: relay listener's reply on loopback (src=loopback:relayPort, dst=loopback:origSrcPort).
        if (ctx.Address.Loopback && p.SourcePort == expectedRelay)
            return HandleRelayReply(ctx, next, p, proto, isIpv6);

        return next(ctx);
    }

    private Task HandleEgress(
        PacketContext ctx, PacketDelegate next, ParsedPacket p,
        byte proto, bool isTcp, bool isIpv6, int expectedRelay)
    {
        IPAddress srcIp = p.Source;
        ushort srcPort = p.SourcePort;
        IPAddress dstIp = p.Destination;
        ushort dstPort = p.DestinationPort;

        FlowKey tcpKey = isTcp ? new FlowKey(proto, srcIp, srcPort, dstIp, dstPort) : default;
        bool tracked = isTcp
            ? _tracker.IsTrackedTcp(tcpKey)
            : _tracker.IsTrackedUdp(srcIp, srcPort);

        // Race fallback: the kernel emits the SYN to the NETWORK layer while the SOCKET event
        // announcing the same connection is still in flight, so a brand-new connection often
        // arrives here "untracked". connect() has already registered the socket in the kernel
        // table by then, so asking the kernel settles it.
        //
        // For a SYN this lookup is not throttled: it is the difference between capturing a new
        // connection and losing it for its whole lifetime. Later packets keep the throttle, since
        // by then the answer cannot change anything (see HandleEscapedFlow).
        bool isSyn = isTcp && IsHandshakeStart(p);
        if (!tracked)
        {
            _tracker.TryReconcileFromKernel(out _, out _, force: isSyn);

            // Re-check unconditionally, NOT only when the reconcile added something. The two pumps
            // run in parallel, so the SOCKET pump often records this very flow in the microseconds
            // between the lookup above and this line — and then the reconcile reports "nothing
            // new" precisely because the flow is already there. Trusting that return value cost
            // every first connection its capture.
            tracked = isTcp
                ? _tracker.IsTrackedTcp(tcpKey)
                : _tracker.IsTrackedUdp(srcIp, srcPort);
            if (tracked)
                _logger.LogTrace("  egress tracked on re-check (the socket event landed meanwhile)");
        }

        if (_logger.IsEnabled(LogLevel.Trace))
            _logger.LogTrace("  egress tracked={Tracked} tcpFlows={FlowCount} natCount={NatCount}",
                tracked, _tracker.TcpSnapshot.Count, _nat.Count);
        if (!tracked) return next(ctx);

        // Destination-port whitelist: tracked packets whose dstPort is outside the configured set
        // bypass NAT entirely and flow straight to the original destination. This means they DO
        // NOT traverse the relay/proxy — the caller opts into that trade-off explicitly.
        if (_dstPortFilter != null && !_dstPortFilter.Contains(dstPort))
        {
            _logger.LogTrace("  not redirecting, dstPort={DstPort} is outside the filter (passthrough)", dstPort);
            return next(ctx);
        }

        // A TCP flow may only be captured from its SYN. If the handshake already started without
        // us — the process was attached mid-flight, or the SOCKET event lost the race against the
        // SYN — then redirecting the rest of it sends the two halves of one connection to two
        // different places and the connection dies. That is strictly worse than the leak it was
        // meant to prevent, so such flows are handled separately.
        if (isTcp && !isSyn && _nat.Find(proto, srcPort, isIpv6) == null)
            return HandleEscapedFlow(ctx, next, srcIp, srcPort, dstIp, dstPort);

        // Which tracked process this packet really belongs to. With several pids tracked at once
        // (root + children, or several unrelated targets) the root pid says nothing, and the NAT
        // entry is what later tells the relay handler whose routing policy applies.
        uint flowPid = isTcp
            ? (_tracker.TryGetTcpProcessId(tcpKey, out uint tcpPid) ? tcpPid : _rootProcessId)
            : (_tracker.TryGetUdpProcessId(srcIp, srcPort, out uint udpPid) ? udpPid : _rootProcessId);

        // Store the real-interface IfIdx so the reply path can reinject on the same interface.
        var entry = new NatEntry(flowPid, proto, srcIp, srcPort, dstIp, dstPort,
            ctx.Address.Network.IfIdx, ctx.Address.Network.SubIfIdx);
        _nat.Upsert(entry);
        if (_logger.IsEnabled(LogLevel.Debug))
        {
            _logger.LogDebug("  nat {Protocol} srcPort={SrcPort} -> {Destination}:{DestinationPort}{Name} ifIdx={IfIdx}",
                isTcp ? "tcp" : "udp", srcPort, dstIp, dstPort,
                _dnsLookup?.Resolve(dstIp) is string name ? $" ({name})" : "",
                ctx.Address.Network.IfIdx);
        }

        IPAddress loopback = isIpv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback;
        p.SetSource(loopback, srcPort);
        p.SetDestination(loopback, (ushort)expectedRelay);

        // Re-inject at the WFP OUTBOUND hook on the loopback interface. The kernel handles both
        // halves of the loopback transmission and delivers the SYN to the relay's listener.
        // Switching to Outbound=false here makes WFP silently drop the packet (no listener match).
        ctx.Address.Loopback = true;
        ctx.Address.Network.IfIdx = 1;
        ctx.Address.Network.SubIfIdx = 0;
        _logger.LogTrace("  -> redirect {Loopback}:{SrcPort} to {Loopback}:{RelayPort}", loopback, srcPort, loopback, expectedRelay);
        ctx.MarkModified();
        return Task.CompletedTask;
    }

    private Task HandleRelayReply(PacketContext ctx, PacketDelegate next, ParsedPacket p, byte proto, bool isIpv6)
    {
        ushort dstPort = p.DestinationPort;
        NatEntry? entry = _nat.Find(proto, dstPort, isIpv6);
        if (entry == null)
        {
            _logger.LogTrace("  reply candidate dstPort={DstPort} ipv6={IsIpv6} has no NAT entry", dstPort, isIpv6);
            return next(ctx);
        }

        // Loopback packets are captured twice (sender outbound + receiver inbound). Handle the
        // outbound capture; the inbound duplicate would otherwise hit a nonexistent socket and
        // produce a spurious RST, so drop it.
        if (!ctx.Address.Outbound)
        {
            _logger.LogTrace("  -> dropping the inbound loopback duplicate");
            ctx.Drop();
            return Task.CompletedTask;
        }

        p.SetSource(entry.OriginalDestinationAddress, entry.OriginalDestinationPort);
        p.SetDestination(entry.OriginalSourceAddress, entry.OriginalSourcePort);

        // Reinject as inbound on the real interface the original socket lives on.
        ctx.Address.Loopback = false;
        ctx.Address.Outbound = false;
        ctx.Address.Network.IfIdx = entry.IfIdx;
        ctx.Address.Network.SubIfIdx = entry.SubIfIdx;
        _logger.LogTrace("  -> reply rewritten to {Source}:{SourcePort} -> {Destination}:{DestinationPort} ifIdx={IfIdx}",
            entry.OriginalDestinationAddress, entry.OriginalDestinationPort,
            entry.OriginalSourceAddress, entry.OriginalSourcePort, entry.IfIdx);
        ctx.MarkModified();
        return Task.CompletedTask;
    }

    // The opening SYN (no ACK): the only packet a flow can be captured from.
    private static bool IsHandshakeStart(ParsedPacket p) => p.Tcp.Syn && !p.Tcp.Ack;

    // A flow that started outside our control. Two honest choices, neither of them "redirect it":
    //   * pass it through (default) — the connection keeps working, but its packets reach the
    //     destination directly, so that one connection reveals the real IP. Sockets a process
    //     already had open when it was attached land here, which is why this is the default:
    //     killing every existing connection of a running browser is not a reasonable greeting.
    //   * block it — nothing leaks; the application sees the connection die and opens a new one,
    //     which is then captured from its SYN. Use when a leak is worse than a stall.
    // Launching the process suspended avoids the situation entirely.
    private Task HandleEscapedFlow(
        PacketContext ctx, PacketDelegate next, IPAddress srcIp, ushort srcPort, IPAddress dstIp, ushort dstPort)
    {
        if (_blockEscapedFlows)
        {
            _logger.LogDebug("dropping escaped flow {Source}:{SourcePort} -> {Destination}:{DestinationPort} (it started before capture)",
                srcIp, srcPort, dstIp, dstPort);
            ctx.Drop();
            return Task.CompletedTask;
        }

        _logger.LogWarning("passing escaped flow {Source}:{SourcePort} -> {Destination}:{DestinationPort} — it started before capture, so the real IP is exposed to this destination",
            srcIp, srcPort, dstIp, dstPort);
        return next(ctx);
    }

    private static string TcpFlags(ParsedPacket p)
    {
        if (!p.IsTcp) return "";
        var t = p.Tcp;
        var sb = new System.Text.StringBuilder(8);
        if (t.Syn) sb.Append('S');
        if (t.Ack) sb.Append('A');
        if (t.Fin) sb.Append('F');
        if (t.Rst) sb.Append('R');
        return sb.Length == 0 ? "-" : sb.ToString();
    }

    private static string Describe(ParsedPacket p, in WinDivertAddress addr, int length)
    {
        string proto = p.IsTcp ? "tcp" : p.IsUdp ? "udp" : ((byte)p.Protocol).ToString();
        string flags = p.IsTcp ? $" flags={TcpFlags(p)}" : "";
        return $"out={(addr.Outbound ? 1 : 0)} lb={(addr.Loopback ? 1 : 0)} if={addr.Network.IfIdx}/{addr.Network.SubIfIdx} {proto} {p.Source}:{p.SourcePort} -> {p.Destination}:{p.DestinationPort} len={length}{flags}";
    }
}
