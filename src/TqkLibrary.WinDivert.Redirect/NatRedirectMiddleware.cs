using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TqkLibrary.WinDivert.Packet;

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

    // Asked before a UDP flow is redirected; null redirects every one. See UdpRedirectPredicate.
    private readonly UdpRedirectPredicate? _shouldRedirectUdp;

    // The redirector's ROOT pid, used only as a fallback when the flow lookup misses. A redirector
    // can follow many pids, so the owner of the packet in hand comes from the tracker.
    private readonly uint _rootProcessId;

    // Escaped flows already reported, so the warning is one per flow rather than one per packet.
    // Cleared wholesale once it grows past the cap: this is log de-duplication, and a flow warned
    // about twice after a long run is a far smaller problem than an unbounded set.
    private const int MaxRememberedEscapedFlows = 4096;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<FlowKey, byte> _warnedEscapedFlows = new();

    // Escaped flows the host has asked to have reset (see IProcessRedirector.ResetEscapedFlows),
    // and the builder for the reset itself. Null = the host never asks, and escaped flows are only
    // ever passed or dropped.
    private readonly EscapedFlowBlocklist? _flowsToReset;
    private readonly TcpResetPacketBuilder _resetBuilder = new TcpResetPacketBuilder();
    private readonly System.Collections.Concurrent.ConcurrentDictionary<FlowKey, byte> _resetFlows = new();

    // Untracked SYNs whose decision is running off the pump — see HoldSynForReconcile.
    private readonly System.Collections.Concurrent.ConcurrentDictionary<FlowKey, byte> _pendingSyns = new();

    public NatRedirectMiddleware(
        INatTable nat,
        ISocketTracker tracker,
        RelayPorts relayPorts,
        RedirectProtocol protocols,
        uint rootProcessId,
        ILogger<NatRedirectMiddleware> logger,
        IDnsCacheLookup? dnsLookup = null,
        IReadOnlyCollection<ushort>? destinationPortFilter = null,
        bool blockEscapedFlows = false,
        UdpRedirectPredicate? shouldRedirectUdp = null,
        EscapedFlowBlocklist? flowsToReset = null)
    {
        _nat = nat ?? throw new ArgumentNullException(nameof(nat));
        _tracker = tracker ?? throw new ArgumentNullException(nameof(tracker));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _dnsLookup = dnsLookup;
        _relayPorts = relayPorts;
        _protocols = protocols;
        _rootProcessId = rootProcessId;
        _blockEscapedFlows = blockEscapedFlows;
        _shouldRedirectUdp = shouldRedirectUdp;
        _flowsToReset = flowsToReset;
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

        // An untracked SYN is decided OFF the pump thread. Its unthrottled kernel sweep used to run
        // right here, and the pump handles every captured packet of the machine: each new
        // connection anywhere stalled everyone else's packets (a game's included) behind a full
        // read of the kernel tables. The SYN is held — dropped now, re-injected once the sweep has
        // answered — and concurrent SYNs share sweeps. See HoldSynForReconcile.
        // A retransmission while the first SYN is still held is dropped even if the flow has
        // become tracked meanwhile: the held copy may already have decided "unchanged", and a
        // second copy rewritten here would send one 4-tuple's handshake to two places.
        if (isSyn && _pendingSyns.ContainsKey(tcpKey))
        {
            ctx.Drop();
            return Task.CompletedTask;
        }

        // A SYN outside the port filter is passed through whatever the sweep says, so it is not
        // worth holding.
        if (!tracked && isSyn)
        {
            if (!PassesPortFilter(dstPort)) return next(ctx);
            return HoldSynForReconcile(ctx, tcpKey, proto, isIpv6, expectedRelay);
        }

        if (!tracked)
        {
            // Any other untracked packet — a UDP datagram, a mid-flow TCP segment — is not waited
            // for: most of them belong to processes nobody tracks, and a synchronous sweep here
            // stalled the whole machine's traffic behind a read of the kernel tables. The sweep
            // runs in the background (throttled); a flow it finds is captured from its next packet.
            _tracker.RequestReconcileFromKernel();

            // Re-check anyway: the two pumps run in parallel, so the SOCKET pump often records this
            // very flow in the microseconds since the lookup above.
            tracked = isTcp
                ? _tracker.IsTrackedTcp(tcpKey)
                : _tracker.IsTrackedUdp(srcIp, srcPort);
            if (tracked && _logger.IsEnabled(LogLevel.Trace))
                _logger.LogTrace("  egress tracked on re-check (the socket event landed meanwhile)");
        }

        if (_logger.IsEnabled(LogLevel.Trace))
            _logger.LogTrace("  egress tracked={Tracked} tcpFlows={FlowCount} natCount={NatCount}",
                tracked, _tracker.TcpSnapshot.Count, _nat.Count);
        if (!tracked) return next(ctx);

        if (!PassesPortFilter(dstPort)) return next(ctx);

        // A TCP flow may only be captured from its SYN. If the handshake already started without
        // us — the process was attached mid-flight, or the SOCKET event lost the race against the
        // SYN — then redirecting the rest of it sends the two halves of one connection to two
        // different places and the connection dies. That is strictly worse than the leak it was
        // meant to prevent, so such flows are handled separately.
        if (isTcp && !isSyn && _nat.Find(proto, srcPort, isIpv6) == null)
            return HandleEscapedFlow(ctx, next, p, srcIp, srcPort, dstIp, dstPort);

        // Which tracked process this packet really belongs to. With several pids tracked at once
        // (root + children, or several unrelated targets) the root pid says nothing, and the NAT
        // entry is what later tells the relay handler whose routing policy applies.
        uint flowPid = isTcp
            ? (_tracker.TryGetTcpProcessId(tcpKey, out uint tcpPid) ? tcpPid : _rootProcessId)
            : (_tracker.TryGetUdpProcessId(srcIp, srcPort, out uint udpPid) ? udpPid : _rootProcessId);

        // The host may want this UDP flow left alone entirely — see UdpRedirectPredicate for why
        // "direct" is something only a non-redirected datagram can deliver.
        //
        // Asked once per flow, and only while the flow has no NAT entry: a flow already redirected
        // keeps being redirected even if the answer would change now (a name learned from a DNS
        // answer in the meantime). Half a flow through the relay and half around it would leave
        // the two halves expecting replies in two different places.
        if (!isTcp && _shouldRedirectUdp != null && _nat.Find(proto, srcPort, isIpv6) == null
            && !AsksToRedirect(flowPid, dstIp, dstPort, isIpv6))
        {
            if (_logger.IsEnabled(LogLevel.Trace))
                _logger.LogTrace("  not redirecting udp {Source}:{SourcePort} -> {Destination}:{DestinationPort}, the host routes it direct (passthrough)",
                    srcIp, srcPort, dstIp, dstPort);
            return next(ctx);
        }

        ctx.ChecksumsUpdated = RedirectToRelay(p, ref ctx.Address, proto, isTcp, isIpv6, expectedRelay, flowPid);
        ctx.MarkModified();
        return Task.CompletedTask;
    }

    // Destination-port whitelist: tracked packets whose dstPort is outside the configured set
    // bypass NAT entirely and flow straight to the original destination. This means they DO NOT
    // traverse the relay/proxy — the caller opts into that trade-off explicitly.
    private bool PassesPortFilter(ushort dstPort)
    {
        if (_dstPortFilter == null || _dstPortFilter.Contains(dstPort)) return true;
        if (_logger.IsEnabled(LogLevel.Trace))
            _logger.LogTrace("  not redirecting, dstPort={DstPort} is outside the filter (passthrough)", dstPort);
        return false;
    }

    // The redirect itself, shared by the pump's own path and the held-SYN path: records the flow
    // in the NAT table and rewrites the packet (in its buffer) and its address onto the relay.
    // The caller decides whether the packet goes out — MarkModified on the pump, Inject off it —
    // and either way the checksums are valid before sending: patched in place when WinDivert
    // marked them valid (returns true, so the pump may skip its recompute), otherwise recomputed
    // by the pump or by Inject.
    private bool RedirectToRelay(
        ParsedPacket p, ref WinDivertAddress address,
        byte proto, bool isTcp, bool isIpv6, int expectedRelay, uint flowPid)
    {
        IPAddress srcIp = p.Source;
        ushort srcPort = p.SourcePort;
        IPAddress dstIp = p.Destination;
        ushort dstPort = p.DestinationPort;

        // Store the real-interface IfIdx so the reply path can reinject on the same interface.
        var entry = new NatEntry(flowPid, proto, srcIp, srcPort, dstIp, dstPort,
            address.Network.IfIdx, address.Network.SubIfIdx);
        // Only the flow's first packet is worth a line. Logging every packet of every flow put a
        // string format, a locked reverse-name lookup and a file write on the pump thread for each
        // one — thousands a second on a browser, and the pump is what the whole machine's traffic
        // waits behind.
        bool isNewFlow = _nat.Upsert(entry);
        if (isNewFlow && _logger.IsEnabled(LogLevel.Debug))
        {
            _logger.LogDebug("  nat {Protocol} srcPort={SrcPort} -> {Destination}:{DestinationPort}{Name} ifIdx={IfIdx}",
                isTcp ? "tcp" : "udp", srcPort, dstIp, dstPort,
                _dnsLookup?.Resolve(dstIp) is string name ? $" ({name})" : "",
                address.Network.IfIdx);
        }

        IPAddress loopback = isIpv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback;
        Span<byte> loopbackBytes = stackalloc byte[isIpv6 ? 16 : 4];
        loopback.TryWriteBytes(loopbackBytes, out _);
        bool checksumsUpdated = p.TryRewriteIncremental(loopbackBytes, srcPort, loopbackBytes, (ushort)expectedRelay, in address);
        if (!checksumsUpdated)
        {
            p.SetSource(loopback, srcPort);
            p.SetDestination(loopback, (ushort)expectedRelay);
        }

        // Re-inject at the WFP OUTBOUND hook on the loopback interface. The kernel handles both
        // halves of the loopback transmission and delivers the SYN to the relay's listener.
        // Switching to Outbound=false here makes WFP silently drop the packet (no listener match).
        address.Loopback = true;
        address.Network.IfIdx = 1;
        address.Network.SubIfIdx = 0;
        if (_logger.IsEnabled(LogLevel.Trace))
            _logger.LogTrace("  -> redirect {Loopback}:{SrcPort} to {Loopback}:{RelayPort}", loopback, srcPort, loopback, expectedRelay);
        return checksumsUpdated;
    }

    // An untracked SYN, decided off the pump thread.
    //
    // The packet is copied out of the pump's buffer (which holds the next packet by the time the
    // task runs) and dropped; the task waits for a kernel sweep that began AFTER the SYN was
    // captured — connect() registered the socket before the SYN existed, so that sweep cannot miss
    // a tracked flow — then re-checks and injects either the redirected SYN or the original bytes,
    // untouched. The SYN is late by one sweep, which is what it used to cost on the pump anyway,
    // except that nobody else waits behind it any more.
    //
    // While a flow's SYN is held, a retransmission of it is simply dropped: the held one will go
    // out, and a second copy deciding in parallel could inject twice. Injected packets carry the
    // impostor flag, which the handle's filter excludes, so they are not captured again.
    private Task HoldSynForReconcile(PacketContext ctx, FlowKey key, byte proto, bool isIpv6, int expectedRelay)
    {
        ctx.Drop();
        if (!_pendingSyns.TryAdd(key, 0))
        {
            if (_logger.IsEnabled(LogLevel.Trace))
                _logger.LogTrace("  dropping a retransmitted SYN for {Flow}, the first one is still held", key);
            return Task.CompletedTask;
        }

        byte[] packet = new byte[ctx.Length];
        Buffer.BlockCopy(ctx.Buffer, 0, packet, 0, ctx.Length);
        WinDivertAddress address = ctx.Address;
        IPacketInjector injector = ctx.Injector;
        CancellationToken token = ctx.CancellationToken;

        _ = Task.Run(() => DecideHeldSynAsync(packet, address, injector, key, proto, isIpv6, expectedRelay, token));
        return Task.CompletedTask;
    }

    private async Task DecideHeldSynAsync(
        byte[] packet, WinDivertAddress address, IPacketInjector injector,
        FlowKey key, byte proto, bool isIpv6, int expectedRelay, CancellationToken token)
    {
        try
        {
            try
            {
                await _tracker.ReconcileFromKernelAsync(token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                return;  // the pump is gone; nothing may be injected for it
            }
            catch (Exception ex)
            {
                // Decide on what the tracker knows anyway — the SOCKET event may well have landed.
                _logger.LogWarning(ex, "kernel reconcile for the held SYN {Flow} failed", key);
            }
            if (token.IsCancellationRequested) return;

            ParsedPacket? p = PacketParser.Default.TryParse(packet, packet.Length);

            // Re-check unconditionally, never on the reconcile's "added" count: the SOCKET pump may
            // have recorded the flow on its own while the sweep ran, and the sweep then reports
            // "nothing new" precisely because the flow is already there.
            bool redirected = false;
            if (p != null && p.IsTcp && _tracker.IsTrackedTcp(key) && PassesPortFilter(p.DestinationPort))
            {
                uint flowPid = _tracker.TryGetTcpProcessId(key, out uint tcpPid) ? tcpPid : _rootProcessId;
                RedirectToRelay(p, ref address, proto, isTcp: true, isIpv6, expectedRelay, flowPid);
                redirected = true;
            }

            if (token.IsCancellationRequested) return;
            bool sent = injector.Inject(packet, packet.Length, address);
            if (_logger.IsEnabled(LogLevel.Trace))
                _logger.LogTrace("  held SYN {Flow} decided off the pump: redirected={Redirected} injected={Injected}",
                    key, redirected, sent);
        }
        catch (Exception ex) when (token.IsCancellationRequested)
        {
            // The handle closed between the last check and Inject: stopping, not a failure.
            _logger.LogDebug(ex, "held SYN {Flow} not injected, the pump stopped", key);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "deciding the held SYN {Flow} failed; it is lost and the process will retransmit", key);
        }
        finally
        {
            _pendingSyns.TryRemove(key, out _);
        }
    }

    private Task HandleRelayReply(PacketContext ctx, PacketDelegate next, ParsedPacket p, byte proto, bool isIpv6)
    {
        ushort dstPort = p.DestinationPort;
        NatEntry? entry = _nat.Find(proto, dstPort, isIpv6);
        if (entry == null)
        {
            if (_logger.IsEnabled(LogLevel.Trace))
                _logger.LogTrace("  reply candidate dstPort={DstPort} ipv6={IsIpv6} has no NAT entry", dstPort, isIpv6);
            return next(ctx);
        }

        // Loopback packets are captured twice (sender outbound + receiver inbound). Handle the
        // outbound capture; the inbound duplicate would otherwise hit a nonexistent socket and
        // produce a spurious RST, so drop it.
        if (!ctx.Address.Outbound)
        {
            if (_logger.IsEnabled(LogLevel.Trace))
                _logger.LogTrace("  -> dropping the inbound loopback duplicate");
            ctx.Drop();
            return Task.CompletedTask;
        }

        int addressLength = isIpv6 ? 16 : 4;
        Span<byte> originalSource = stackalloc byte[addressLength];
        Span<byte> originalDestination = stackalloc byte[addressLength];
        bool restored = entry.OriginalDestinationAddress.TryWriteBytes(originalSource, out int sourceLength) && sourceLength == addressLength
            && entry.OriginalSourceAddress.TryWriteBytes(originalDestination, out int destinationLength) && destinationLength == addressLength;
        if (restored && p.TryRewriteIncremental(originalSource, entry.OriginalDestinationPort, originalDestination, entry.OriginalSourcePort, in ctx.Address))
            ctx.ChecksumsUpdated = true;
        else
        {
            p.SetSource(entry.OriginalDestinationAddress, entry.OriginalDestinationPort);
            p.SetDestination(entry.OriginalSourceAddress, entry.OriginalSourcePort);
        }

        // Reinject as inbound on the real interface the original socket lives on.
        ctx.Address.Loopback = false;
        ctx.Address.Outbound = false;
        ctx.Address.Network.IfIdx = entry.IfIdx;
        ctx.Address.Network.SubIfIdx = entry.SubIfIdx;
        if (_logger.IsEnabled(LogLevel.Trace))
            _logger.LogTrace("  -> reply rewritten to {Source}:{SourcePort} -> {Destination}:{DestinationPort} ifIdx={IfIdx}",
                entry.OriginalDestinationAddress, entry.OriginalDestinationPort,
                entry.OriginalSourceAddress, entry.OriginalSourcePort, entry.IfIdx);
        ctx.MarkModified();
        return Task.CompletedTask;
    }

    // The host's answer, with a failure treated as "redirect". Erring towards the relay is the
    // safe half of the trade: a datagram redirected when it need not have been costs a lost reply,
    // while one passed by mistake has already put the machine's real address on the wire.
    private bool AsksToRedirect(uint processId, IPAddress destination, ushort destinationPort, bool isIpv6)
    {
        try
        {
            return _shouldRedirectUdp!(processId, destination, destinationPort, isIpv6);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "the UDP redirect predicate threw for pid={Pid} -> {Destination}:{DestinationPort}; redirecting, which never leaks",
                processId, destination, destinationPort);
            return true;
        }
    }

    // The opening SYN (no ACK): the only packet a flow can be captured from.
    private static bool IsHandshakeStart(ParsedPacket p) => p.Tcp.Syn && !p.Tcp.Ack;

    // A flow that started outside our control. Three honest choices, none of them "redirect it":
    //   * pass it through (default) — the connection keeps working, but its packets reach the
    //     destination directly, so that one connection reveals the real IP. Sockets a process
    //     already had open when it was attached land here, which is why this is the default:
    //     killing every existing connection of a running browser is not a reasonable greeting.
    //   * block it — nothing leaks; the application sees the connection die and opens a new one,
    //     which is then captured from its SYN. Use when a leak is worse than a stall.
    //   * reset it, when the host asked for this particular flow (ResetEscapedFlows) — the packet
    //     is dropped and the process is handed the RST its peer would have sent, so the socket
    //     fails at once instead of waiting out a retransmission timer, and the application's
    //     reconnect is captured from its SYN. Blocking alone leaves the process retransmitting into
    //     silence for a minute or more.
    // Launching the process suspended avoids the situation entirely.
    private Task HandleEscapedFlow(
        PacketContext ctx, PacketDelegate next, ParsedPacket p, IPAddress srcIp, ushort srcPort, IPAddress dstIp, ushort dstPort)
    {
        if (_flowsToReset != null)
        {
            var key = new FlowKey(6, srcIp, srcPort, dstIp, dstPort);
            if (_flowsToReset.Contains(key))
            {
                ResetTowardsProcess(ctx, p, key);
                ctx.Drop();
                return Task.CompletedTask;
            }
        }

        if (_blockEscapedFlows)
        {
            _logger.LogDebug("dropping escaped flow {Source}:{SourcePort} -> {Destination}:{DestinationPort} (it started before capture)",
                srcIp, srcPort, dstIp, dstPort);
            ctx.Drop();
            return Task.CompletedTask;
        }

        // Once per flow, not once per packet: an escaped connection carrying a video stream would
        // otherwise write this warning thousands of times, from the pump thread, saying the same
        // thing about the same flow.
        if (_warnedEscapedFlows.TryAdd(new FlowKey(6, srcIp, srcPort, dstIp, dstPort), 0))
        {
            if (_warnedEscapedFlows.Count > MaxRememberedEscapedFlows) _warnedEscapedFlows.Clear();
            _logger.LogWarning("passing escaped flow {Source}:{SourcePort} -> {Destination}:{DestinationPort} — it started before capture, so the real IP is exposed to this destination",
                srcIp, srcPort, dstIp, dstPort);
        }
        return next(ctx);
    }

    // The reset goes in the direction the peer's packets take: inbound, on the interface the
    // process's own packet was leaving from, so the stack matches it to the socket. The packet it
    // answers is dropped by the caller; a peer that never sees it has nothing to reply to.
    private void ResetTowardsProcess(PacketContext ctx, ParsedPacket p, FlowKey key)
    {
        byte[] reset;
        try
        {
            reset = _resetBuilder.BuildResetTowardsSender(p);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "could not build a reset for {Flow}; dropping the packet only", key);
            return;
        }

        WinDivertAddress addr = default;
        addr.Layer = WinDivertLayer.Network;
        addr.Outbound = false;
        addr.Loopback = false;
        addr.IPv6 = p.IsIpv6;
        addr.Network.IfIdx = ctx.Address.Network.IfIdx;
        addr.Network.SubIfIdx = ctx.Address.Network.SubIfIdx;

        bool injected = ctx.Injector.Inject(reset, reset.Length, addr);

        // Once per flow: the process may send a few more segments before it takes the reset in.
        if (_resetFlows.TryAdd(key, 0))
        {
            if (_resetFlows.Count > MaxRememberedEscapedFlows) _resetFlows.Clear();
            _logger.LogDebug("resetting pre-existing flow {Flow} at the host's request, injected={Injected}", key, injected);
        }
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
