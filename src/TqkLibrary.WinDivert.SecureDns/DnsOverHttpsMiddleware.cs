using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TqkLibrary.WinDivert.Flow;
using TqkLibrary.WinDivert.Native;
using TqkLibrary.WinDivert.Packet;
using TqkLibrary.WinDivert.Pipeline;

namespace TqkLibrary.WinDivert.SecureDns;

/// <summary>
/// Intercepts outbound UDP/53 (classic DNS) over IPv4 or IPv6, resolves it over HTTPS, and injects
/// the answer back to the asker as an inbound UDP packet. <see cref="DnsInterceptScope"/> decides
/// whose queries: the target processes' only (the default), or the whole machine's — so DNS keeps
/// working even when the proxy carrying the rest of the traffic cannot tunnel UDP (HTTP CONNECT,
/// SOCKS4), and stays private from whoever watches the real network.
/// </summary>
/// <remarks>
/// The original query is dropped immediately; the HTTPS round-trip and the injection happen on a
/// bounded background task, because the recv pump must never block on network I/O. Everything the
/// task needs is copied out of the shared pump buffer BEFORE InvokeAsync returns — the buffer
/// holds the next packet by the time the task runs.
///
/// Loop safety: when the DoH endpoint is a host name rather than an IP literal, the resolver's own
/// lookup of that name goes through the OS resolver and, machine-wide, would land right back here
/// — waiting on itself. Queries for exactly that name are therefore always let through untouched.
/// </remarks>
public sealed class DnsOverHttpsMiddleware : IPacketMiddleware
{
    private const ushort DnsPort = 53;

    private readonly IDnsResolver _resolver;
    private readonly ISocketTracker _tracker;
    private readonly IDnsMessageParser _parser;
    private readonly ILogger<DnsOverHttpsMiddleware> _logger;
    private readonly SemaphoreSlim _concurrency;
    private readonly int _maxPendingQueries;
    private int _pendingQueries;
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
    {
        _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
        _tracker = tracker ?? throw new ArgumentNullException(nameof(tracker));
        _parser = parser ?? throw new ArgumentNullException(nameof(parser));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _reverseDns = reverseDns;
        if (maxConcurrentQueries < 1) maxConcurrentQueries = 1;
        _concurrency = new SemaphoreSlim(maxConcurrentQueries, maxConcurrentQueries);
        _scope = scope;
        _maxPendingQueries = maxPendingQueries < 1 ? 1 : maxPendingQueries;
        Uri? endpoint = resolver.Endpoint;
        _endpointHost = endpoint != null && endpoint.HostNameType == UriHostNameType.Dns
            ? endpoint.IdnHost.TrimEnd('.')
            : null;
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

        // Copy the DNS query payload + the 5-tuple/interface out of the shared buffer NOW.
        int payloadOffset = p.Udp.PayloadOffset;
        int available = ctx.Length - payloadOffset;
        int udpPayloadLen = p.Udp.PayloadLength;
        int payloadLen = (udpPayloadLen >= 0 && udpPayloadLen < available) ? udpPayloadLen : available;
        if (payloadLen <= 0)
        {
            ctx.Drop();
            return Task.CompletedTask;
        }

        if (IsEndpointLookup(ctx.Buffer, payloadOffset, payloadLen)) return next(ctx);

        byte[] query = new byte[payloadLen];
        Buffer.BlockCopy(ctx.Buffer, payloadOffset, query, 0, payloadLen);

        IPAddress clientIp = p.Source;
        ushort clientPort = p.SourcePort;
        IPAddress serverIp = p.Destination;
        bool ipv6 = p.IsIpv6;
        uint ifIdx = ctx.Address.Network.IfIdx;
        uint subIfIdx = ctx.Address.Network.SubIfIdx;
        IPacketInjector injector = ctx.Injector;
        CancellationToken token = ctx.CancellationToken;

        // Swallow the original query; the resolved answer is injected later (a SERVFAIL on failure).
        ctx.Drop();

        // Queued + running queries are bounded: a flood must not pile up tasks behind the semaphore.
        // The excess gets an immediate SERVFAIL (cheap, built and injected right here) so its client
        // moves on instead of waiting out its own timeout.
        if (Interlocked.Increment(ref _pendingQueries) > _maxPendingQueries)
        {
            Interlocked.Decrement(ref _pendingQueries);
            _logger.LogTrace("DoH backlog full ({Max}), SERVFAIL for query from {Client}:{ClientPort}",
                _maxPendingQueries, clientIp, clientPort);
            byte[]? servFail = DnsServFail.Build(query);
            if (servFail != null)
            {
                try { InjectReply(servFail, clientIp, clientPort, serverIp, ipv6, ifIdx, subIfIdx, injector); }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "DoH SERVFAIL injection failed for {Client}:{ClientPort}", clientIp, clientPort);
                }
            }
            return Task.CompletedTask;
        }

        _ = Task.Run(async () =>
        {
            try { await ResolveAndInjectAsync(query, clientIp, clientPort, serverIp, ipv6, ifIdx, subIfIdx, injector, token).ConfigureAwait(false); }
            finally { Interlocked.Decrement(ref _pendingQueries); }
        });
        return Task.CompletedTask;
    }

    private async Task ResolveAndInjectAsync(
        byte[] query, IPAddress clientIp, ushort clientPort, IPAddress serverIp, bool ipv6,
        uint ifIdx, uint subIfIdx, IPacketInjector injector, CancellationToken token)
    {
        try { await _concurrency.WaitAsync(token).ConfigureAwait(false); }
        catch (OperationCanceledException) { return; }

        try
        {
            byte[]? response = null;
            try
            {
                response = await _resolver.ResolveAsync(query, token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { return; }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "DoH resolve failed for {Client}:{ClientPort}", clientIp, clientPort);
            }

            if (response == null || response.Length == 0)
            {
                // Fail fast: an immediate SERVFAIL lets the client move on instead of timing out.
                response = DnsServFail.Build(query);
                if (response == null) return;
                _logger.LogDebug("{Client}:{ClientPort} answered with SERVFAIL (DoH gave no answer)", clientIp, clientPort);
            }
            else if (_reverseDns != null)
            {
                var records = _parser.ParseAddressAnswers(response, 0, response.Length);
                if (records.Count > 0) _reverseDns.AddRange(records);
            }

            InjectReply(response, clientIp, clientPort, serverIp, ipv6, ifIdx, subIfIdx, injector);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "DoH answer injection failed for {Client}:{ClientPort}", clientIp, clientPort);
        }
        finally
        {
            _concurrency.Release();
        }
    }

    private void InjectReply(
        byte[] response, IPAddress clientIp, ushort clientPort, IPAddress serverIp, bool ipv6,
        uint ifIdx, uint subIfIdx, IPacketInjector injector)
    {
        byte[] packet = _replyBuilder.Build(serverIp, clientIp, clientPort, response);
        WinDivertAddress addr = BuildInboundAddress(ipv6, ifIdx, subIfIdx);
        bool ok = injector.Inject(packet, packet.Length, addr);
        _logger.LogTrace("{Client}:{ClientPort} answered from {Server}:{DnsPort}, resp={Bytes}B inject={Injected}",
            clientIp, clientPort, serverIp, DnsPort, response.Length, ok);
    }

    // True for a query asking the DoH endpoint's own name, which must reach the OS resolver's real
    // server: answering it over DoH would need that very answer first.
    private bool IsEndpointLookup(byte[] buffer, int offset, int length)
        => _endpointHost != null
            && _parser.TryReadQuestionName(buffer, offset, length, out string name)
            && string.Equals(name.TrimEnd('.'), _endpointHost, StringComparison.OrdinalIgnoreCase);

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
}
