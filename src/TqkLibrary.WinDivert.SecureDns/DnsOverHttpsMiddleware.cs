using System;
using System.Diagnostics;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TqkLibrary.WinDivert.Flow;
using TqkLibrary.WinDivert.SecureDns.Helpers;
using TqkLibrary.WinDivert.Native;
using TqkLibrary.WinDivert.Packet;
using TqkLibrary.WinDivert.Pipeline;

namespace TqkLibrary.WinDivert.SecureDns;

/// <summary>
/// Intercepts outbound UDP/53 (classic DNS) over IPv4 or IPv6, resolves it over HTTPS, and injects
/// the answer back to the asker as an inbound UDP packet. Two ways to choose which queries: a fixed
/// resolver plus a <see cref="DnsInterceptScope"/> (the target processes' only, or the whole
/// machine's), or a <see cref="DnsQueryDecider"/> asked per query machine-wide, which picks
/// pass-through or the resolver to use. Either way DNS keeps working even when the proxy carrying
/// the rest of the traffic cannot tunnel UDP (HTTP CONNECT, SOCKS4), and stays private from
/// whoever watches the real network.
/// </summary>
/// <remarks>
/// The original query is dropped immediately; the HTTPS round-trip and the injection happen on a
/// bounded background task, because the recv pump must never block on network I/O. Everything the
/// task needs is copied out of the shared pump buffer BEFORE InvokeAsync returns — the buffer
/// holds the next packet by the time the task runs.
///
/// Loop safety (fixed-resolver mode): when the DoH endpoint is a host name rather than an IP
/// literal, the resolver's own lookup of that name goes through the OS resolver and, machine-wide,
/// would land right back here — waiting on itself. Queries for exactly that name are therefore
/// always let through untouched. In decider mode that choice belongs to the decider.
///
/// Plain-DNS fallback (decider mode): a failed lookup re-sends the original query packet, with the
/// address it was captured with, through the same injector the pump uses to pass packets on — the
/// very send <c>next(ctx)</c> would have caused — so the handle's <c>not impostor</c> filter keeps
/// it from being captured again.
/// </remarks>
public sealed class DnsOverHttpsMiddleware : IPacketMiddleware
{
    private const ushort DnsPort = 53;

    // Exactly one of these two is set: a fixed resolver, or a per-query decider.
    private readonly IDnsResolver? _resolver;
    private readonly DnsQueryDecider? _decider;
    private readonly ISocketTracker _tracker;
    private readonly IDnsMessageParser _parser;
    private readonly ILogger<DnsOverHttpsMiddleware> _logger;
    private readonly SemaphoreSlim _concurrency;
    private readonly int _maxPendingQueries;
    private int _pendingQueries;
    private int _deciderThrewLogged;
    // Plain-DNS fallbacks can come once per query while an endpoint is down: one warning per interval.
    private readonly LogThrottle _fallbackThrottle = new LogThrottle(TimeSpan.FromSeconds(30));
    private readonly DnsInterceptScope _scope;
    private readonly DnsReplyPacketBuilder _replyBuilder = new DnsReplyPacketBuilder();

    // The DoH endpoint's own host name, or null for an IP-literal endpoint. See the class remarks.
    private readonly string? _endpointHost;

    // DoH answers are the only DNS the process ever sees while this stage is on, so they are also
    // the only source of IP to domain knowledge. Feeding them back keeps domain routing working.
    private readonly IReverseDnsTable? _reverseDns;

    public DnsOverHttpsMiddleware(
        IDnsResolver resolver,
        ISocketTracker tracker,
        IDnsMessageParser parser,
        ILogger<DnsOverHttpsMiddleware> logger,
        IReverseDnsTable? reverseDns = null,
        int maxConcurrentQueries = 32,
        DnsInterceptScope scope = DnsInterceptScope.TrackedProcesses,
        int maxPendingQueries = 256)
        : this(tracker, parser, logger, reverseDns, maxConcurrentQueries, maxPendingQueries)
    {
        _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
        _scope = scope;
        _endpointHost = GetEndpointHost(resolver.Endpoint);
    }

    /// <summary>
    /// Decider mode: every process's outbound DNS/53 is offered to <paramref name="decider"/>, on
    /// the pump thread, which says whether and through which resolver it is answered. The resolvers
    /// it hands out stay owned by the caller.
    /// </summary>
    public DnsOverHttpsMiddleware(
        DnsQueryDecider decider,
        ISocketTracker tracker,
        IDnsMessageParser parser,
        ILogger<DnsOverHttpsMiddleware> logger,
        IReverseDnsTable? reverseDns = null,
        int maxConcurrentQueries = 32,
        int maxPendingQueries = 256)
        : this(tracker, parser, logger, reverseDns, maxConcurrentQueries, maxPendingQueries)
    {
        _decider = decider ?? throw new ArgumentNullException(nameof(decider));
        _scope = DnsInterceptScope.WholeMachine;
    }

    private DnsOverHttpsMiddleware(
        ISocketTracker tracker,
        IDnsMessageParser parser,
        ILogger<DnsOverHttpsMiddleware> logger,
        IReverseDnsTable? reverseDns,
        int maxConcurrentQueries,
        int maxPendingQueries)
    {
        _tracker = tracker ?? throw new ArgumentNullException(nameof(tracker));
        _parser = parser ?? throw new ArgumentNullException(nameof(parser));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _reverseDns = reverseDns;
        if (maxConcurrentQueries < 1) maxConcurrentQueries = 1;
        _concurrency = new SemaphoreSlim(maxConcurrentQueries, maxConcurrentQueries);
        _maxPendingQueries = maxPendingQueries < 1 ? 1 : maxPendingQueries;
    }

    public Task InvokeAsync(PacketContext ctx, PacketDelegate next)
    {
        ParsedPacket? p = ctx.Packet;
        // Scope: outbound UDP/53 on a real interface, from a target process or from anyone.
        if (p == null || !p.IsUdp) return next(ctx);
        if (!ctx.Address.Outbound || ctx.Address.Loopback) return next(ctx);
        if (p.DestinationPort != DnsPort) return next(ctx);
        if (_scope == DnsInterceptScope.TrackedProcesses && !_tracker.IsTrackedUdp(p.Source, p.SourcePort))
            return next(ctx);

        int payloadOffset = p.Udp.PayloadOffset;
        int available = ctx.Length - payloadOffset;
        int udpPayloadLen = p.Udp.PayloadLength;
        int payloadLen = (udpPayloadLen >= 0 && udpPayloadLen < available) ? udpPayloadLen : available;

        IDnsResolver resolver;
        bool fallback;
        string? queryName = null;
        if (_decider != null)
        {
            if (payloadLen <= 0) return next(ctx);
            if (!TryDecide(ctx, p, payloadOffset, payloadLen, out DnsQueryDecision decision, out queryName)) return next(ctx);
            resolver = decision.Resolver!;
            fallback = decision.FallbackToPlainDnsOnFailure;
        }
        else
        {
            if (payloadLen <= 0)
            {
                ctx.Drop();
                return Task.CompletedTask;
            }
            if (IsEndpointLookup(ctx.Buffer, payloadOffset, payloadLen)) return next(ctx);
            resolver = _resolver!;
            fallback = false;
        }

        // Queued + running queries are bounded: a flood must not pile up tasks behind the semaphore.
        // The excess gets an immediate SERVFAIL (cheap, built and injected right here) so its client
        // moves on instead of waiting out its own timeout — or, with fallback, just goes out as
        // plain DNS.
        if (Interlocked.Increment(ref _pendingQueries) > _maxPendingQueries)
        {
            Interlocked.Decrement(ref _pendingQueries);
            if (fallback)
            {
                if (_logger.IsEnabled(LogLevel.Debug))
                    _logger.LogDebug("DoH backlog full ({Max}), query {Query} from {Client}:{ClientPort} goes out as plain DNS",
                        _maxPendingQueries, queryName, p.Source, p.SourcePort);
                return next(ctx);
            }
            if (_logger.IsEnabled(LogLevel.Debug))
                _logger.LogDebug("DoH backlog full ({Max}), SERVFAIL for query {Query} from {Client}:{ClientPort}",
                    _maxPendingQueries, queryName, p.Source, p.SourcePort);
            byte[]? servFail = DnsServFail.Build(CopyPayload(ctx, payloadOffset, payloadLen));
            ReplyTarget excess = CaptureReplyTarget(ctx, p);
            ctx.Drop();
            if (servFail != null)
            {
                try { InjectReply(servFail, excess); }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "DoH SERVFAIL injection failed for {Client}:{ClientPort}", excess.ClientIp, excess.ClientPort);
                }
            }
            return Task.CompletedTask;
        }

        // Copy the DNS query payload + the 5-tuple/interface out of the shared buffer NOW.
        byte[] query = CopyPayload(ctx, payloadOffset, payloadLen);
        ReplyTarget target = CaptureReplyTarget(ctx, p);
        // The whole original packet + its address, re-sent as plain DNS should the lookup fail.
        OriginalQuery? original = null;
        if (fallback)
        {
            byte[] packet = new byte[ctx.Length];
            Buffer.BlockCopy(ctx.Buffer, 0, packet, 0, ctx.Length);
            original = new OriginalQuery(packet, ctx.Address);
        }
        CancellationToken token = ctx.CancellationToken;
        long startedAt = Stopwatch.GetTimestamp();

        // Swallow the original query; the resolved answer is injected later (on failure a SERVFAIL,
        // or the original query itself with fallback).
        ctx.Drop();

        _ = Task.Run(async () =>
        {
            try { await ResolveAndInjectAsync(resolver, query, target, original, queryName, startedAt, token).ConfigureAwait(false); }
            finally { Interlocked.Decrement(ref _pendingQueries); }
        });
        return Task.CompletedTask;
    }

    // Asks the decider about one query. False means let it through: decided so, unparseable, or
    // the decider threw — a broken decider must not take the machine's DNS down with it.
    private bool TryDecide(PacketContext ctx, ParsedPacket p, int payloadOffset, int payloadLen, out DnsQueryDecision decision, out string? queryName)
    {
        decision = DnsQueryDecision.Pass;
        queryName = null;
        if (!_parser.TryReadQuestion(ctx.Buffer, payloadOffset, payloadLen, out string name, out ushort type))
            return false;

        uint? pid = _tracker.TryGetUdpProcessId(p.Source, p.SourcePort, out uint found) ? found : null;
        var info = new DnsQueryInfo(pid, name.TrimEnd('.').ToLowerInvariant(), type, p.IsIpv6);
        try
        {
            decision = _decider!(in info);
        }
        catch (Exception ex)
        {
            // Only the first throw is a warning; a decider that keeps throwing must not flood the log.
            LogLevel level = Interlocked.Exchange(ref _deciderThrewLogged, 1) == 0 ? LogLevel.Warning : LogLevel.Debug;
            _logger.Log(level, ex, "DNS query decider threw for {Query}; letting it through", info);
            decision = DnsQueryDecision.Pass;
        }
        if (decision.IsPass) return false;
        queryName = info.QueryName;

        // Safety net: a resolver must never be asked for its own endpoint's name, or its lookup of
        // that name would wait on itself. Let that query through to the OS resolver's real server.
        string? endpointHost = GetEndpointHost(decision.Resolver!.Endpoint);
        if (endpointHost != null && string.Equals(info.QueryName, endpointHost, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogDebug("DNS query for {Query} is the picked resolver's own endpoint name; letting it through", info);
            decision = DnsQueryDecision.Pass;
            return false;
        }
        return true;
    }

    private async Task ResolveAndInjectAsync(
        IDnsResolver resolver, byte[] query, ReplyTarget target, OriginalQuery? original,
        string? queryName, long startedAt, CancellationToken token)
    {
        try { await _concurrency.WaitAsync(token).ConfigureAwait(false); }
        catch (OperationCanceledException) { return; }

        try
        {
            byte[]? response = null;
            string failure = "no answer";
            try
            {
                response = await resolver.ResolveAsync(query, token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { return; }
            catch (ObjectDisposedException ex)
            {
                // The caller disposed the resolver while this query was in flight: an ordinary
                // failure (fallback or SERVFAIL below), not worth a warning.
                failure = "resolver disposed";
                _logger.LogDebug(ex, "DoH resolver was disposed during the lookup for {Client}:{ClientPort}", target.ClientIp, target.ClientPort);
            }
            catch (Exception ex)
            {
                failure = ex.GetType().Name + ": " + ex.Message;
                _logger.LogWarning(ex, "DoH resolve failed for {Client}:{ClientPort}", target.ClientIp, target.ClientPort);
            }

            bool servFailed = false;
            if (response == null || response.Length == 0)
            {
                if (original != null)
                {
                    // Fallback: the query goes on to its real server as if it had never been taken.
                    bool sent = target.Injector.Inject(original.Packet, original.Packet.Length, original.Address);
                    if (_fallbackThrottle.TryEnter(out int heldBack))
                    {
                        _logger.LogWarning(
                            "DoH gave no answer ({Reason}) via {Endpoint}; queries sent as plain DNS ({HeldBack} more not logged)",
                            failure, resolver.Endpoint, heldBack);
                    }
                    if (_logger.IsEnabled(LogLevel.Debug))
                        _logger.LogDebug("{Client}:{ClientPort} {Query} fell back to plain DNS after {Ms} ms ({Reason}), inject={Injected}",
                            target.ClientIp, target.ClientPort, queryName, ElapsedMs(startedAt), failure, sent);
                    return;
                }
                // Fail fast: an immediate SERVFAIL lets the client move on instead of timing out.
                servFailed = true;
                response = DnsServFail.Build(query);
                if (response == null) return;
                if (_logger.IsEnabled(LogLevel.Debug))
                    _logger.LogDebug("{Client}:{ClientPort} {Query} SERVFAIL after {Ms} ms ({Reason})",
                        target.ClientIp, target.ClientPort, queryName, ElapsedMs(startedAt), failure);
            }
            else if (_reverseDns != null)
            {
                var records = _parser.ParseAddressAnswers(response, 0, response.Length);
                if (records.Count > 0) _reverseDns.AddRange(records);
            }

            InjectReply(response, target);
            if (!servFailed && _logger.IsEnabled(LogLevel.Debug))
                _logger.LogDebug("{Client}:{ClientPort} {Query} answered in {Ms} ms ({Bytes} B)",
                    target.ClientIp, target.ClientPort, queryName, ElapsedMs(startedAt), response.Length);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "DoH answer injection failed for {Client}:{ClientPort}", target.ClientIp, target.ClientPort);
        }
        finally
        {
            _concurrency.Release();
        }
    }

    private static double ElapsedMs(long startedAt)
        => (Stopwatch.GetTimestamp() - startedAt) * 1000.0 / Stopwatch.Frequency;

    private void InjectReply(byte[] response, ReplyTarget target)
    {
        byte[] packet = _replyBuilder.Build(target.ServerIp, target.ClientIp, target.ClientPort, response);
        WinDivertAddress addr = BuildInboundAddress(target.Ipv6, target.IfIdx, target.SubIfIdx);
        bool ok = target.Injector.Inject(packet, packet.Length, addr);
        _logger.LogTrace("{Client}:{ClientPort} answered from {Server}:{DnsPort}, resp={Bytes}B inject={Injected}",
            target.ClientIp, target.ClientPort, target.ServerIp, DnsPort, response.Length, ok);
    }

    private static byte[] CopyPayload(PacketContext ctx, int payloadOffset, int payloadLen)
    {
        byte[] query = new byte[payloadLen];
        Buffer.BlockCopy(ctx.Buffer, payloadOffset, query, 0, payloadLen);
        return query;
    }

    private static ReplyTarget CaptureReplyTarget(PacketContext ctx, ParsedPacket p)
        => new ReplyTarget(p.Source, p.SourcePort, p.Destination, p.IsIpv6,
            ctx.Address.Network.IfIdx, ctx.Address.Network.SubIfIdx, ctx.Injector);

    // True for a query asking the DoH endpoint's own name, which must reach the OS resolver's real
    // server: answering it over DoH would need that very answer first.
    private bool IsEndpointLookup(byte[] buffer, int offset, int length)
        => _endpointHost != null
            && _parser.TryReadQuestionName(buffer, offset, length, out string name)
            && string.Equals(name.TrimEnd('.'), _endpointHost, StringComparison.OrdinalIgnoreCase);

    // The endpoint's host name, or null for an IP-literal (or missing) endpoint.
    private static string? GetEndpointHost(Uri? endpoint)
        => endpoint != null && endpoint.HostNameType == UriHostNameType.Dns
            ? endpoint.IdnHost.TrimEnd('.')
            : null;

    // Inbound on the real interface the query left from — mirrors how the NAT stage reply leg
    // delivers (Outbound=false, Loopback=false, original IfIdx).
    private static WinDivertAddress BuildInboundAddress(bool ipv6, uint ifIdx, uint subIfIdx)
    {
        WinDivertAddress addr = default;
        addr.Layer = WinDivertLayer.Network;
        addr.Outbound = false;
        addr.Loopback = false;
        addr.IPv6 = ipv6;
        addr.Network.IfIdx = ifIdx;
        addr.Network.SubIfIdx = subIfIdx;
        return addr;
    }

    // Who the answer goes back to, copied out of the pump's packet.
    private sealed record ReplyTarget(
        IPAddress ClientIp, ushort ClientPort, IPAddress ServerIp, bool Ipv6,
        uint IfIdx, uint SubIfIdx, IPacketInjector Injector);

    // The untouched query packet and the address it was captured with.
    private sealed record OriginalQuery(byte[] Packet, WinDivertAddress Address);
}
