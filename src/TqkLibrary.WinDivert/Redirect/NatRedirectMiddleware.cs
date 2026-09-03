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
// deferred to the rest of the chain via next() — so it must run first in the IPv4 pipeline.
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
    // Which protocols this stage NAT-redirects. The handle's filter may capture more (e.g. UDP for
    // a downstream DNS/block middleware); packets of a protocol not in this set are deferred via
    // next() so NAT never redirects them.
    private readonly RedirectProtocol _protocols;
    // null = redirect every destination port; non-null = whitelist (only ports in the set are
    // NAT-redirected, all others pass through to their real destination).
    private readonly HashSet<ushort>? _dstPortFilter;

    public NatRedirectMiddleware(
        int tcpRelayPort,
        int udpRelayPort,
        RedirectProtocol protocols,
        IReadOnlyCollection<ushort>? destinationPortFilter = null)
    {
        _tcpRelayPort = tcpRelayPort;
        _udpRelayPort = udpRelayPort;
        _protocols = protocols;
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
        int expectedRelay = isTcp ? _tcpRelayPort : _udpRelayPort;

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

            // Race fallback: kernel may emit the SYN to the Network layer before the SOCKET-layer
            // pump has added the FlowKey. Refresh from the kernel TCP/UDP table (throttled) and recheck.
            if (!tracked && ctx.Tracker.TryReconcileFromKernel(out _, out _))
            {
                tracked = isTcp
                    ? ctx.Tracker.IsTrackedTcp(tcpKey)
                    : ctx.Tracker.IsTrackedUdp(srcIp, srcPort);
                if (tracked)
                    ctx.Logger.Log("INT", "  egress reconciled from kernel table");
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

            IPAddress loopback = p.IsIpv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback;
            p.SetSource(loopback, srcPort);
            p.SetDestination(loopback, (ushort)expectedRelay);

            // Re-inject at the WFP OUTBOUND hook on the loopback interface. The kernel handles
            // both halves of the loopback transmission and delivers the SYN to the relay's listener.
            // Switching to Outbound=false here causes WFP to silently drop the packet (no listener match).
            ctx.Address.Loopback = true;
            ctx.Address.Network.IfIdx = 1;
            ctx.Address.Network.SubIfIdx = 0;
            ctx.Logger.Log("INT", $"  -> REDIRECT 127.0.0.1:{srcPort} -> 127.0.0.1:{expectedRelay} (Outbound=true Loopback=true IfIdx=1)");
            ctx.MarkModified();
            return Task.CompletedTask;
        }

        // Case 2: relay listener's reply on loopback (src=loopback:relayPort, dst=loopback:origSrcPort).
        if (ctx.Address.Loopback && p.SourcePort == expectedRelay)
        {
            ushort dstPort = p.DestinationPort;
            NatEntry? entry = ctx.Nat.Find(proto, dstPort);
            ctx.Logger.Log("INT", $"  reply candidate dstPort={dstPort} natHit={(entry != null)} addr.Outbound={ctx.Address.Outbound}");
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
