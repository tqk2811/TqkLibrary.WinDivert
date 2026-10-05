using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using TqkLibrary.WinDivert.Flow.Interfaces;
using TqkLibrary.WinDivert.Flow.Models;
using TqkLibrary.WinDivert.Native.Models;
using TqkLibrary.WinDivert.Packet;
using TqkLibrary.WinDivert.Packet.Models;
using TqkLibrary.WinDivert.Pipeline;
using TqkLibrary.WinDivert.Pipeline.Enums;
using TqkLibrary.WinDivert.Pipeline.Interfaces;
using TqkLibrary.WinDivert.Pipeline.Models;
using TqkLibrary.WinDivert.SecureDns;
using TqkLibrary.WinDivert.SecureDns.Enums;
using TqkLibrary.WinDivert.SecureDns.Interfaces;
using TqkLibrary.WinDivert.SecureDns.Models;
using Xunit;

namespace TqkLibrary.WinDivert.Tests;

/// <summary>
/// Which DNS/53 the DoH stage takes over, and the reply it injects in place of the real answer.
/// </summary>
public class DnsOverHttpsMiddlewareTests
{
    private static readonly IPAddress ClientV4 = IPAddress.Parse("192.168.1.20");
    private static readonly IPAddress ServerV4 = IPAddress.Parse("192.168.1.1");
    private static readonly IPAddress ClientV6 = IPAddress.Parse("2001:db8::20");
    private static readonly IPAddress ServerV6 = IPAddress.Parse("2001:db8::1");
    private const ushort ClientPort = 50123;

    private static readonly byte[] Answer = { 0xAB, 0xCD, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0 };

    [Fact]
    public async Task WholeMachineTakesAQueryFromASocketNobodyTracks()
    {
        var injector = new RecordingInjector();
        var middleware = Create(DnsInterceptScope.WholeMachine, new StubResolver(Answer));

        PacketContext ctx = Query(ClientV4, ServerV4, "example.com", injector);
        bool passed = await InvokeAsync(middleware, ctx);

        Assert.False(passed);
        Assert.Equal(PacketDisposition.Drop, ctx.Disposition);
        (byte[] packet, WinDivertAddress addr) = await injector.NextAsync();
        Assert.False(addr.Outbound);
        Assert.False(addr.IPv6);

        ParsedPacket reply = new PacketParser().TryParse(packet, packet.Length)!;
        Assert.Equal(ServerV4, reply.Source);
        Assert.Equal(ClientV4, reply.Destination);
        Assert.Equal(53, reply.SourcePort);
        Assert.Equal(ClientPort, reply.DestinationPort);
    }

    [Fact]
    public async Task WholeMachineAnswersIpv6WithAnIpv6Reply()
    {
        var injector = new RecordingInjector();
        var middleware = Create(DnsInterceptScope.WholeMachine, new StubResolver(Answer));

        PacketContext ctx = Query(ClientV6, ServerV6, "example.com", injector);
        await InvokeAsync(middleware, ctx);

        Assert.Equal(PacketDisposition.Drop, ctx.Disposition);
        (byte[] packet, WinDivertAddress addr) = await injector.NextAsync();
        Assert.True(addr.IPv6);
        Assert.Equal(6, packet[0] >> 4);
    }

    [Fact]
    public async Task AResolverThatThrowsGetsASERVFAILInjectedWithTheSameId()
    {
        var injector = new RecordingInjector();
        var middleware = Create(DnsInterceptScope.WholeMachine, new StubResolver(Answer) { Throw = true });

        await InvokeAsync(middleware, Query(ClientV4, ServerV4, "example.com", injector));

        (byte[] packet, _) = await injector.NextAsync();
        byte[] dns = packet[28..];  // IPv4 header 20 + UDP header 8
        Assert.Equal(0x12, dns[0]);
        Assert.Equal(0x34, dns[1]);
        Assert.NotEqual(0, dns[2] & 0x80);          // QR
        Assert.Equal(0x01, dns[2] & 0x01);          // RD kept
        Assert.NotEqual(0, dns[3] & 0x80);          // RA
        Assert.Equal(2, dns[3] & 0x0F);             // RCODE = SERVFAIL
        Assert.Equal(1, (dns[4] << 8) | dns[5]);    // question kept
        Assert.All(dns[6..12], b => Assert.Equal(0, b));
        Assert.Equal(DnsQuery("example.com").Length, dns.Length);  // the question is kept, nothing after it
    }

    [Fact]
    public async Task AnEmptyAnswerGetsASERVFAILToo()
    {
        var injector = new RecordingInjector();
        var middleware = Create(DnsInterceptScope.WholeMachine, new StubResolver(Array.Empty<byte>()));

        await InvokeAsync(middleware, Query(ClientV4, ServerV4, "example.com", injector));

        (byte[] packet, _) = await injector.NextAsync();
        Assert.Equal(2, packet[28 + 3] & 0x0F);
    }

    [Fact]
    public async Task ACancelledResolveInjectsNothing()
    {
        var injector = new RecordingInjector();
        var resolver = new StubResolver(Answer) { WaitForCancel = true };
        var middleware = Create(DnsInterceptScope.WholeMachine, resolver);
        using var cts = new CancellationTokenSource();

        await InvokeAsync(middleware, Query(ClientV4, ServerV4, "example.com", injector, cts.Token));
        await resolver.WaitForCallAsync();
        cts.Cancel();
        await resolver.WaitForExitAsync();
        await Task.Delay(50);  // let the middleware finish handling the cancellation

        Assert.Equal(0, injector.Count);
    }

    // An HttpClient timeout surfaces as a TaskCanceledException while the pump token is still live.
    [Fact]
    public async Task AResolverTimeoutWithoutCancellationGetsASERVFAIL()
    {
        var injector = new RecordingInjector();
        var resolver = new StubResolver(Answer) { ThrowCancel = true };
        var middleware = Create(DnsInterceptScope.WholeMachine, resolver);

        await InvokeAsync(middleware, Query(ClientV4, ServerV4, "example.com", injector));

        (byte[] packet, _) = await injector.NextAsync();
        Assert.Equal(2, packet[28 + 3] & 0x0F);
    }

    [Fact]
    public void ASERVFAILKeepsOnlyTheCheckingDisabledBit()
    {
        byte[] query = DnsQuery("example.com");
        query[3] = 0x30;  // AD + CD set in the query
        byte[]? reply = (byte[]?)typeof(DnsOverHttpsMiddleware).Assembly
            .GetType("TqkLibrary.WinDivert.SecureDns.DnsServFail")!
            .GetMethod("Build")!.Invoke(null, new object[] { query });

        Assert.Equal(0x80 | 0x10 | 0x02, reply![3]);
    }

    // Queued + running queries are capped; the excess gets a SERVFAIL without ever reaching the resolver.
    [Fact]
    public async Task QueriesBeyondThePendingCapGetASERVFAILWithoutResolving()
    {
        var gate = new TaskCompletionSource<byte[]?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var resolver = new StubResolver(Answer) { Gate = gate.Task };
        var injector = new RecordingInjector();
        var middleware = new DnsOverHttpsMiddleware(
            resolver, new StubTracker(), new DnsMessageParser(),
            NullLogger<DnsOverHttpsMiddleware>.Instance,
            maxConcurrentQueries: 1, scope: DnsInterceptScope.WholeMachine, maxPendingQueries: 2);

        PacketContext[] ctxs = Enumerable.Range(0, 5)
            .Select(_ => Query(ClientV4, ServerV4, "example.com", injector)).ToArray();
        foreach (PacketContext ctx in ctxs) await InvokeAsync(middleware, ctx);

        Assert.All(ctxs, c => Assert.Equal(PacketDisposition.Drop, c.Disposition));
        await resolver.WaitForCallAsync();
        // The 3 excess queries were answered on the spot, while the gate still holds the other 2.
        for (int i = 0; i < 3; i++)
        {
            (byte[] packet, _) = await injector.NextAsync();
            Assert.Equal(2, packet[28 + 3] & 0x0F);  // SERVFAIL
        }
        Assert.Equal(0, injector.Count);
        Assert.Equal(1, resolver.Calls);  // 1 running + 1 queued; the other 3 never got a task

        gate.SetResult(Answer);
        for (int i = 0; i < 2; i++)
        {
            (byte[] packet, _) = await injector.NextAsync();
            Assert.Equal(0, packet[28 + 3] & 0x0F);  // the real answer
        }
        await Task.Delay(50);  // settle: nothing more may arrive
        Assert.Equal(2, resolver.Calls);
        Assert.Equal(0, injector.Count);
    }

    [Fact]
    public async Task TrackedOnlyLeavesAQueryFromAnUntrackedSocketAlone()
    {
        var resolver = new StubResolver(Answer);
        var middleware = Create(DnsInterceptScope.TrackedProcesses, resolver);

        PacketContext ctx = Query(ClientV4, ServerV4, "example.com", new RecordingInjector());

        Assert.True(await InvokeAsync(middleware, ctx));
        Assert.Equal(PacketDisposition.Pass, ctx.Disposition);
        Assert.Equal(0, resolver.Calls);
    }

    [Fact]
    public async Task TrackedOnlyStillTakesAQueryFromATrackedSocket()
    {
        var tracker = new StubTracker { TrackedUdp = (ClientV4, ClientPort) };
        var middleware = Create(DnsInterceptScope.TrackedProcesses, new StubResolver(Answer), tracker);

        PacketContext ctx = Query(ClientV4, ServerV4, "example.com", new RecordingInjector());

        Assert.False(await InvokeAsync(middleware, ctx));
        Assert.Equal(PacketDisposition.Drop, ctx.Disposition);
    }

    [Theory]
    [InlineData(true, false)]   // inbound
    [InlineData(false, true)]   // loopback
    public async Task InboundAndLoopbackAreNeverTaken(bool inbound, bool loopback)
    {
        var resolver = new StubResolver(Answer);
        var middleware = Create(DnsInterceptScope.WholeMachine, resolver);

        PacketContext ctx = Query(ClientV4, ServerV4, "example.com", new RecordingInjector());
        ctx.Address.Outbound = !inbound;
        ctx.Address.Loopback = loopback;

        Assert.True(await InvokeAsync(middleware, ctx));
        Assert.Equal(PacketDisposition.Pass, ctx.Disposition);
        Assert.Equal(0, resolver.Calls);
    }

    // The resolver's own lookup of a host-name endpoint goes out through the OS resolver; taking
    // it machine-wide would leave DoH waiting on an answer only DoH could give.
    [Fact]
    public async Task TheLookupOfTheEndpointsOwnNameIsLetThrough()
    {
        var resolver = new StubResolver(Answer, new Uri("https://dns.google/dns-query"));
        var middleware = Create(DnsInterceptScope.WholeMachine, resolver);

        PacketContext own = Query(ClientV4, ServerV4, "DNS.google", new RecordingInjector());
        Assert.True(await InvokeAsync(middleware, own));
        Assert.Equal(0, resolver.Calls);

        PacketContext other = Query(ClientV4, ServerV4, "example.com", new RecordingInjector());
        Assert.False(await InvokeAsync(middleware, other));
    }

    [Fact]
    public void Ipv6ReplyCarriesTheRightHeaderAndAValidUdpChecksum()
    {
        byte[] payload = { 1, 2, 3, 4, 5 };  // odd length, to exercise the padding byte
        byte[] packet = new DnsReplyPacketBuilder().Build(ServerV6, ClientV6, ClientPort, payload);

        Assert.Equal(40 + 8 + payload.Length, packet.Length);
        Assert.Equal(0x60, packet[0]);
        Assert.Equal(8 + payload.Length, (packet[4] << 8) | packet[5]);  // payload length
        Assert.Equal(17, packet[6]);                                      // next header = UDP
        Assert.True(packet[7] > 0);                                       // hop limit
        Assert.Equal(ServerV6.GetAddressBytes(), packet[8..24]);
        Assert.Equal(ClientV6.GetAddressBytes(), packet[24..40]);
        Assert.Equal(53, (packet[40] << 8) | packet[41]);
        Assert.Equal(ClientPort, (packet[42] << 8) | packet[43]);
        Assert.Equal(8 + payload.Length, (packet[44] << 8) | packet[45]);
        Assert.Equal(payload, packet[48..]);

        // Summing the pseudo-header and the datagram, checksum included, must fold to all ones.
        Assert.NotEqual(0, (packet[46] << 8) | packet[47]);
        Assert.Equal(0xFFFF, OnesComplementSum(packet));

        ParsedPacket parsed = new PacketParser().TryParse(packet, packet.Length)!;
        Assert.True(parsed.IsIpv6);
        Assert.True(parsed.IsUdp);
    }

    private static int OnesComplementSum(byte[] packet)
    {
        int udpLen = packet.Length - 40;
        long sum = udpLen + 17;
        for (int i = 8; i < 40; i += 2) sum += (packet[i] << 8) | packet[i + 1];
        for (int i = 40; i < packet.Length; i += 2)
            sum += (packet[i] << 8) | (i + 1 < packet.Length ? packet[i + 1] : 0);
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (int)sum;
    }

    // ---- decider mode ----------------------------------------------------------------------

    [Fact]
    public async Task DeciderPassHandsTheQueryOnAndInjectsNothing()
    {
        var injector = new RecordingInjector();
        var resolver = new StubResolver(Answer);
        int asked = 0;
        var middleware = Create((in DnsQueryInfo _) => { asked++; return DnsQueryDecision.Pass; });

        PacketContext ctx = Query(ClientV4, ServerV4, "example.com", injector);
        bool passed = await InvokeAsync(middleware, ctx);

        Assert.True(passed);
        Assert.Equal(1, asked);
        Assert.NotEqual(PacketDisposition.Drop, ctx.Disposition);
        Assert.Equal(0, injector.Count);
        Assert.Equal(0, resolver.Calls);
    }

    [Fact]
    public async Task DeciderResolveUsesThePickedResolverAndInjectsItsAnswer()
    {
        var injector = new RecordingInjector();
        var other = new StubResolver(Answer);
        var picked = new StubResolver(Answer);
        var middleware = Create((in DnsQueryInfo _) => DnsQueryDecision.Resolve(picked, false));

        PacketContext ctx = Query(ClientV6, ServerV6, "example.com", injector);
        bool passed = await InvokeAsync(middleware, ctx);

        Assert.False(passed);
        Assert.Equal(PacketDisposition.Drop, ctx.Disposition);
        (byte[] packet, WinDivertAddress addr) = await injector.NextAsync();
        Assert.False(addr.Outbound);
        Assert.True(addr.IPv6);
        Assert.Equal(0xAB, packet[40 + 8]);  // the stub's answer id, after the IPv6 + UDP headers
        Assert.Equal(1, picked.Calls);
        Assert.Equal(0, other.Calls);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task DeciderGetsThePidOnlyWhenTheSocketIsTracked(bool tracked)
    {
        var tracker = new StubTracker { UdpOwner = tracked ? (ClientV4, ClientPort, 4242u) : null };
        DnsQueryInfo? seen = null;
        var middleware = Create((in DnsQueryInfo q) => { seen = q; return DnsQueryDecision.Pass; }, tracker);

        await InvokeAsync(middleware, Query(ClientV4, ServerV4, "example.com", new RecordingInjector()));

        Assert.NotNull(seen);
        Assert.Equal(tracked ? 4242u : (uint?)null, seen.Value.ProcessId);
        Assert.False(seen.Value.IsIpv6);
    }

    [Fact]
    public async Task DeciderGetsTheLowerCasedNameAndTheQueryType()
    {
        DnsQueryInfo? seen = null;
        var middleware = Create((in DnsQueryInfo q) => { seen = q; return DnsQueryDecision.Pass; });

        await InvokeAsync(middleware, Query(ClientV4, ServerV4, "WWW.Example.COM", new RecordingInjector(), qtype: 28));

        Assert.NotNull(seen);
        Assert.Equal("www.example.com", seen.Value.QueryName);
        Assert.Equal((ushort)28, seen.Value.QueryType);
    }

    [Fact]
    public async Task ADeciderThatThrowsLetsTheQueryThrough()
    {
        var injector = new RecordingInjector();
        var middleware = Create((in DnsQueryInfo _) => throw new InvalidOperationException("decider broke"));

        PacketContext ctx = Query(ClientV4, ServerV4, "example.com", injector);
        bool passed = await InvokeAsync(middleware, ctx);

        Assert.True(passed);
        Assert.NotEqual(PacketDisposition.Drop, ctx.Disposition);
        Assert.Equal(0, injector.Count);
    }

    // A resolver with a host-name endpoint must not be asked for that very name.
    [Fact]
    public async Task DeciderPicksAResolverForItsOwnEndpointNameAndTheQueryPassesThrough()
    {
        var injector = new RecordingInjector();
        var resolver = new StubResolver(Answer, new Uri("https://dns.google/dns-query"));
        var middleware = Create((in DnsQueryInfo _) => DnsQueryDecision.Resolve(resolver, false));

        PacketContext ctx = Query(ClientV4, ServerV4, "DNS.google", injector);
        bool passed = await InvokeAsync(middleware, ctx);

        Assert.True(passed);
        Assert.NotEqual(PacketDisposition.Drop, ctx.Disposition);
        Assert.Equal(0, injector.Count);
        Assert.Equal(0, resolver.Calls);
    }

    // With fallback the failed lookup sends the untouched query on outbound, not a SERVFAIL back.
    [Fact]
    public async Task FallbackReinjectsTheOriginalQueryOutboundWhenTheResolverFails()
    {
        var injector = new RecordingInjector();
        var resolver = new StubResolver(Answer) { Throw = true };
        var middleware = Create((in DnsQueryInfo _) => DnsQueryDecision.Resolve(resolver, true));

        PacketContext ctx = Query(ClientV4, ServerV4, "example.com", injector);
        byte[] original = ctx.Buffer[..ctx.Length];
        bool passed = await InvokeAsync(middleware, ctx);

        Assert.False(passed);
        Assert.Equal(PacketDisposition.Drop, ctx.Disposition);
        (byte[] packet, WinDivertAddress addr) = await injector.NextAsync();
        Assert.True(addr.Outbound);
        Assert.False(addr.Loopback);
        Assert.Equal(original, packet);
    }

    [Fact]
    public async Task WithoutFallbackAFailedResolveGetsASERVFAIL()
    {
        var injector = new RecordingInjector();
        var resolver = new StubResolver(Answer) { Throw = true };
        var middleware = Create((in DnsQueryInfo _) => DnsQueryDecision.Resolve(resolver, false));

        await InvokeAsync(middleware, Query(ClientV4, ServerV4, "example.com", injector));

        (byte[] packet, WinDivertAddress addr) = await injector.NextAsync();
        Assert.False(addr.Outbound);
        Assert.Equal(2, packet[28 + 3] & 0x0F);  // SERVFAIL
    }

    // Over the pending cap, a fallback query simply goes on as plain DNS instead of a SERVFAIL.
    [Fact]
    public async Task FallbackPassesAQueryBeyondThePendingCap()
    {
        var gate = new TaskCompletionSource<byte[]?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var resolver = new StubResolver(Answer) { Gate = gate.Task };
        var injector = new RecordingInjector();
        var middleware = new DnsOverHttpsMiddleware(
            (in DnsQueryInfo _) => DnsQueryDecision.Resolve(resolver, true),
            new StubTracker(), new DnsMessageParser(), NullLogger<DnsOverHttpsMiddleware>.Instance,
            maxConcurrentQueries: 1, maxPendingQueries: 1);

        PacketContext first = Query(ClientV4, ServerV4, "example.com", injector);
        PacketContext second = Query(ClientV4, ServerV4, "example.com", injector);
        Assert.False(await InvokeAsync(middleware, first));
        await resolver.WaitForCallAsync();
        bool secondPassed = await InvokeAsync(middleware, second);

        Assert.True(secondPassed);
        Assert.NotEqual(PacketDisposition.Drop, second.Disposition);
        Assert.Equal(0, injector.Count);

        gate.SetResult(Answer);
        (byte[] packet, _) = await injector.NextAsync();
        Assert.Equal(0, packet[28 + 3] & 0x0F);  // the first query's real answer
        Assert.Equal(1, resolver.Calls);
    }

    // ---- helpers ---------------------------------------------------------------------------

    private static DnsOverHttpsMiddleware Create(DnsQueryDecider decider, ISocketTracker? tracker = null)
        => new DnsOverHttpsMiddleware(
            decider, tracker ?? new StubTracker(), new DnsMessageParser(),
            NullLogger<DnsOverHttpsMiddleware>.Instance);

    private static DnsOverHttpsMiddleware Create(
        DnsInterceptScope scope, IDnsResolver resolver, ISocketTracker? tracker = null)
        => new DnsOverHttpsMiddleware(
            resolver, tracker ?? new StubTracker(), new DnsMessageParser(),
            NullLogger<DnsOverHttpsMiddleware>.Instance, scope: scope);

    // True when the middleware handed the packet on rather than claiming it.
    private static async Task<bool> InvokeAsync(DnsOverHttpsMiddleware middleware, PacketContext ctx)
    {
        bool passed = false;
        await middleware.InvokeAsync(ctx, _ => { passed = true; return Task.CompletedTask; });
        return passed;
    }

    // An outbound client:ClientPort -> server:53 query for `name`, as the pump would hand it over.
    private static PacketContext Query(
        IPAddress client, IPAddress server, string name, IPacketInjector injector,
        CancellationToken token = default, ushort qtype = 1)
    {
        byte[] dns = DnsQuery(name, qtype);
        // The reply builder makes a well-formed datagram with source port 53; a query is the same
        // shape with the client's ephemeral port as its source.
        byte[] packet = new DnsReplyPacketBuilder().Build(client, server, 53, dns);
        var parser = new PacketParser();
        parser.TryParse(packet, packet.Length)!.SetSource(client, ClientPort);

        var ctx = new PacketContext(packet, injector, token)
        {
            Length = packet.Length,
            Packet = parser.TryParse(packet, packet.Length),
        };
        ctx.Address.Outbound = true;
        ctx.Address.Loopback = false;
        ctx.Address.IPv6 = client.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        return ctx;
    }

    private static byte[] DnsQuery(string name, ushort qtype = 1)
    {
        var bytes = new List<byte> { 0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 };
        foreach (string label in name.Split('.'))
        {
            bytes.Add((byte)label.Length);
            bytes.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
        }
        bytes.AddRange(new byte[] { 0, (byte)(qtype >> 8), (byte)qtype, 0, 1 });  // root, qtype, class IN
        return bytes.ToArray();
    }

    private sealed class StubResolver : IDnsResolver
    {
        private readonly byte[] _answer;
        private int _calls;

        public StubResolver(byte[] answer, Uri? endpoint = null)
        {
            _answer = answer;
            Endpoint = endpoint ?? new Uri("https://1.1.1.1/dns-query");
        }

        public Uri Endpoint { get; }
        public int Calls => Volatile.Read(ref _calls);

        public bool Throw { get; init; }
        public bool ThrowCancel { get; init; }
        public bool WaitForCancel { get; init; }
        public Task<byte[]?>? Gate { get; init; }

        private readonly TaskCompletionSource _called = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task WaitForCallAsync() => _called.Task.WaitAsync(TimeSpan.FromSeconds(5));

        private readonly TaskCompletionSource _exited = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task WaitForExitAsync() => _exited.Task.WaitAsync(TimeSpan.FromSeconds(5));

        public async Task<byte[]?> ResolveAsync(byte[] dnsWireQuery, CancellationToken ct)
        {
            Interlocked.Increment(ref _calls);
            _called.TrySetResult();
            try
            {
                if (Gate != null) return await Gate;
                if (WaitForCancel) await Task.Delay(Timeout.Infinite, ct);
                if (ThrowCancel) throw new TaskCanceledException("timed out");  // token not cancelled
                if (Throw) throw new InvalidOperationException("resolver failed");
                return _answer;
            }
            finally { _exited.TrySetResult(); }
        }

        public void Dispose() { }
    }

    private sealed class RecordingInjector : IPacketInjector
    {
        private readonly BlockingCollection<(byte[], WinDivertAddress)> _sent = new();

        public int Count => _sent.Count;

        public bool Inject(byte[] buffer, int length, in WinDivertAddress addr)
        {
            _sent.Add((buffer[..length], addr));
            return true;
        }

        public Task<(byte[] Packet, WinDivertAddress Address)> NextAsync()
            => Task.Run(() =>
            {
                Assert.True(_sent.TryTake(out var item, TimeSpan.FromSeconds(5)), "nothing was injected");
                return item;
            });
    }

    private sealed class StubTracker : ISocketTracker
    {
        public (IPAddress Address, ushort Port)? TrackedUdp { get; init; }
        public (IPAddress Address, ushort Port, uint Pid)? UdpOwner { get; init; }

        public event Action<FlowKey>? TcpConnectEstablished { add { } remove { } }
        public event Action<FlowKey>? TcpConnectClosed { add { } remove { } }
        public event Action<IPAddress, ushort>? UdpBindAdded { add { } remove { } }
        public event Action<IPAddress, ushort>? UdpBindRemoved { add { } remove { } }

        public IReadOnlyCollection<uint> TrackedProcessIds => Array.Empty<uint>();
        public IReadOnlyCollection<FlowKey> TcpSnapshot => Array.Empty<FlowKey>();

        public void Start() { }
        public void AddProcess(uint pid) { }
        public bool RemoveProcess(uint pid) => false;
        public bool IsTrackedProcess(uint pid) => false;
        public bool IsTrackedTcp(FlowKey key) => false;

        public bool IsTrackedUdp(IPAddress localAddr, ushort localPort)
            => TrackedUdp is { } t && t.Address.Equals(localAddr) && t.Port == localPort;

        public bool TryGetTcpProcessId(FlowKey key, out uint processId) { processId = 0; return false; }
        public bool TryGetUdpProcessId(IPAddress localAddr, ushort localPort, out uint processId)
        {
            processId = 0;
            if (UdpOwner is not { } o || !o.Address.Equals(localAddr) || o.Port != localPort) return false;
            processId = o.Pid;
            return true;
        }

        public bool TryReconcileFromKernel(out int tcpAdded, out int udpAdded, bool force = false)
        {
            tcpAdded = udpAdded = 0;
            return false;
        }

        public void Dispose() { }
    }
}
