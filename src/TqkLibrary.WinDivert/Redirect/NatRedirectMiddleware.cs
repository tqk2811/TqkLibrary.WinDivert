using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using TqkLibrary.WinDivert.Flow;
using TqkLibrary.WinDivert.Packet;
using TqkLibrary.WinDivert.Pipeline;

namespace TqkLibrary.WinDivert.Redirect;

// Core NAT logic on the NETWORK layer, as a middleware. Captures both the egress path from the
// target process (to rewrite destination onto the relay) and the loopback reply path from the
// relay (to rewrite the source back to the original destination). Packets it does not claim are
// deferred to the rest of the chain via next() — so it must run first in its pipeline. The same
// class serves both families: it is registered once in the IPv4 pipeline and once in the IPv6 one,
// each time carrying the relay ports of that family (see ProcessRedirector).
//
// Outbound (target-process -> real destination):
//   (srcA:sp, dstB:bp) -> (srcLoopback:sp, dstLoopback:relayPort)
//   NAT stores: srcPort sp -> { origSrcIp=A, origDst=B:bp, pid }
//
// Inbound on loopback (relay -> target-process):
//   (srcLoopback:relayPort, dstLoopback:sp) -> (srcB:bp, dstA:sp)
//   Looked up by dstPort=sp.
public sealed class NatRedirectMiddleware : IPacketMiddleware
{
    private readonly int _tcpRelayPort;
    private readonly int _udpRelayPort;
    // The IPv6 relay listens on its own loopback sockets, so it has its own pair of ports. Zero
    // means "this pipeline does not NAT IPv6" — an IPv6 packet is then deferred to next().
    private readonly int _tcpRelayPortV6;
    private readonly int _udpRelayPortV6;
    // Which protocols this stage NAT-redirects. The handle's filter may capture more (e.g. UDP for
    // a downstream DNS/block middleware); packets of a protocol not in this set are deferred via
    // next() so NAT never redirects them.
    private readonly RedirectProtocol _protocols;
    // null = redirect every destination port; non-null = whitelist (only ports in the set are
    // NAT-redirected, all others pass through to their real destination).
    private readonly HashSet<ushort>? _dstPortFilter;

    // What to do with a TCP flow whose handshake started before this stage could claim it — see
    // HandleEscapedFlow.
    private readonly bool _blockEscapedFlows;

    public NatRedirectMiddleware(
        int tcpRelayPort,
        int udpRelayPort,
        RedirectProtocol protocols,
        IReadOnlyCollection<ushort>? destinationPortFilter = null,
        bool blockEscapedFlows = false,
        int tcpRelayPortV6 = 0,
        int udpRelayPortV6 = 0)
    {
        _tcpRelayPort = tcpRelayPort;
        _udpRelayPort = udpRelayPort;
        _tcpRelayPortV6 = tcpRelayPortV6;
        _udpRelayPortV6 = udpRelayPortV6;
        _protocols = protocols;
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
        int expectedRelay = isTcp
            ? (isIpv6 ? _tcpRelayPortV6 : _tcpRelayPort)
            : (isIpv6 ? _udpRelayPortV6 : _udpRelayPort);
        // No relay socket for this family: nothing here can redirect the packet, so let the rest
        // of the chain (block/observe middlewares) decide what happens to it.
        if (expectedRelay == 0)
            return next(ctx);

        ctx.Logger.Log("INT", $"recv {Describe(p, ctx.Address, ctx.Length)}");

        // Case 1: egress from target process on a real interface → redirect to local relay.
        if (ctx.Address.Outbound && !ctx.Address.Loopback)
        {
            IPAddress srcIp = p.Source;
            ushort srcPort = p.SourcePort;
            IPAddress dstIp = p.Destination;
            ushort dstPort = p.DestinationPort;

            FlowKey tcpKey = isTcp ? new FlowKey(proto, srcIp, srcPort, dstIp, dstPort) : default;
            bool tracked = isTcp
                ? ctx.Tracker.IsTrackedTcp(tcpKey)
                : ctx.Tracker.IsTrackedUdp(srcIp, srcPort);

            // Race fallback: the kernel emits the SYN to the NETWORK layer while the SOCKET event
            // announcing the same connection is still in flight, so a brand-new connection often
            // arrives here "untracked". connect() has already registered the socket in the kernel
            // table by then, so asking the kernel settles it.
            //
            // For a SYN this lookup is not throttled: it is the difference between capturing a new
            // connection and losing it for its whole lifetime. Later packets keep the throttle,
            // since by then the answer cannot change anything (see HandleEscapedFlow).
            bool isSyn = isTcp && IsHandshakeStart(p);
            if (!tracked)
            {
                ctx.Tracker.TryReconcileFromKernel(out _, out _, force: isSyn);

                // Re-check unconditionally, NOT only when the reconcile added something. The two
                // pumps run in parallel, so the SOCKET pump often records this very flow in the
                // microseconds between the lookup above and this line — and then the reconcile
                // reports "nothing new" precisely because the flow is already there. Trusting that
                // return value cost every first connection its capture.
                tracked = isTcp
                    ? ctx.Tracker.IsTrackedTcp(tcpKey)
                    : ctx.Tracker.IsTrackedUdp(srcIp, srcPort);
                if (tracked)
                    ctx.Logger.Log("INT", "  egress tracked on re-check (socket event landed meanwhile)");
            }

            ctx.Logger.Log("INT", $"  egress tracked={tracked} tcpFlows={ctx.Tracker.TcpSnapshot.Count} natCount={ctx.Nat.Count}");
            if (!tracked) return next(ctx);

            // Destination-port whitelist: tracked packets whose dstPort is outside the configured
            // set bypass NAT entirely and flow straight to the original destination. This means
            // they DO NOT traverse the relay/proxy — caller opts into this trade-off explicitly.
            if (_dstPortFilter != null && !_dstPortFilter.Contains(dstPort))
            {
                ctx.Logger.Log("INT", $"  -> SKIP redirect, dstPort={dstPort} not in filter (passthrough)");
                return next(ctx);
            }

            // A TCP flow may only be captured from its SYN. If the handshake already started
            // without us — the process was attached mid-flight, or the SOCKET event lost the race
            // against the SYN — then redirecting the rest of it sends the two halves of one
            // connection to two different places and the connection dies. That is strictly worse
            // than the leak it was meant to prevent, so such flows are handled separately.
            if (isTcp && !isSyn && ctx.Nat.Find(proto, srcPort, isIpv6) == null)
                return HandleEscapedFlow(ctx, next, srcIp, srcPort, dstIp, dstPort);

            // Which tracked process this packet really belongs to. With several pids tracked at
            // once (root + children, or several unrelated targets) the redirector's root pid says
            // nothing, and the NAT entry is what later tells the relay handler whose routing
            // policy applies. Fall back to the root pid only if the flow lookup misses.
            uint flowPid = isTcp
                ? (ctx.Tracker.TryGetTcpProcessId(tcpKey, out uint tcpPid) ? tcpPid : ctx.ProcessId)
                : (ctx.Tracker.TryGetUdpProcessId(srcIp, srcPort, out uint udpPid) ? udpPid : ctx.ProcessId);

            // Store the real-interface IfIdx so the reply path can reinject on the same interface.
            var entry = new NatEntry(flowPid, proto, srcIp, srcPort, dstIp, dstPort, ctx.Address.Network.IfIdx, ctx.Address.Network.SubIfIdx);
            ctx.Nat.Upsert(entry);
            string? dnsName = ctx.DnsLookup?.Resolve(dstIp);
            string dnsTag = dnsName != null ? $" name={dnsName}" : "";
            ctx.Logger.Log("INT", $"  nat.upsert {(isTcp ? "tcp" : "udp")} srcPort={srcPort} -> origDst={dstIp}:{dstPort}{dnsTag} ifIdx={ctx.Address.Network.IfIdx}");

            IPAddress loopback = isIpv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback;
            p.SetSource(loopback, srcPort);
            p.SetDestination(loopback, (ushort)expectedRelay);

            // Re-inject at the WFP OUTBOUND hook on the loopback interface. The kernel handles
            // both halves of the loopback transmission and delivers the SYN to the relay's listener.
            // Switching to Outbound=false here causes WFP to silently drop the packet (no listener match).
            ctx.Address.Loopback = true;
            ctx.Address.Network.IfIdx = 1;
            ctx.Address.Network.SubIfIdx = 0;
            ctx.Logger.Log("INT", $"  -> REDIRECT {loopback}:{srcPort} -> {loopback}:{expectedRelay} (Outbound=true Loopback=true IfIdx=1)");
            ctx.MarkModified();
            return Task.CompletedTask;
        }

        // Case 2: relay listener's reply on loopback (src=loopback:relayPort, dst=loopback:origSrcPort).
        if (ctx.Address.Loopback && p.SourcePort == expectedRelay)
        {
            ushort dstPort = p.DestinationPort;
            NatEntry? entry = ctx.Nat.Find(proto, dstPort, isIpv6);
            ctx.Logger.Log("INT", $"  reply candidate dstPort={dstPort} ipv6={isIpv6} natHit={(entry != null)} addr.Outbound={ctx.Address.Outbound}");
            if (entry == null) return next(ctx);

            // Loopback packets are captured twice (sender outbound + receiver inbound). Handle on
            // the outbound capture; the inbound duplicate would otherwise hit a nonexistent socket
            // and produce a spurious RST, so drop it.
            if (!ctx.Address.Outbound)
            {
                ctx.Logger.Log("INT", "  -> DROP loopback inbound duplicate");
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
            ctx.Logger.Log("INT", $"  -> REPLY rewrite to {entry.OriginalDestinationAddress}:{entry.OriginalDestinationPort} -> {entry.OriginalSourceAddress}:{entry.OriginalSourcePort} ifIdx={entry.IfIdx}");
            ctx.MarkModified();
            return Task.CompletedTask;
        }

        return next(ctx);
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
            ctx.Logger.Log("INT", $"  -> DROP escaped flow {srcIp}:{srcPort} -> {dstIp}:{dstPort} (started before capture)");
            ctx.Drop();
            return Task.CompletedTask;
        }

        ctx.Logger.Log("INT", $"  -> PASS escaped flow {srcIp}:{srcPort} -> {dstIp}:{dstPort} (started before capture; IP is exposed to this destination)");
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
