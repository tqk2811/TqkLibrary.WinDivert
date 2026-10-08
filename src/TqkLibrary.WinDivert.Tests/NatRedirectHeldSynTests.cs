using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using TqkLibrary.WinDivert.Flow;
using TqkLibrary.WinDivert.Flow.Interfaces;
using TqkLibrary.WinDivert.Flow.Models;
using TqkLibrary.WinDivert.Native.Models;
using TqkLibrary.WinDivert.Packet;
using TqkLibrary.WinDivert.Pipeline.Enums;
using TqkLibrary.WinDivert.Pipeline.Interfaces;
using TqkLibrary.WinDivert.Pipeline.Models;
using TqkLibrary.WinDivert.Redirect;
using TqkLibrary.WinDivert.Redirect.Enums;
using TqkLibrary.WinDivert.Redirect.Models;
using Xunit;

namespace TqkLibrary.WinDivert.Tests;

/// <summary>
/// An untracked SYN is decided off the pump thread: dropped, then re-injected (redirected or
/// untouched) once a kernel sweep that began after it has answered.
/// </summary>
public class NatRedirectHeldSynTests
{
    private const int RelayPort = 5000;
    private const ushort RemotePort = 443;
    private static readonly IPAddress Local = IPAddress.Parse("192.168.1.20");
    private static readonly IPAddress Remote = IPAddress.Parse("93.184.216.34");

    [Fact]
    public async Task AnUntrackedSynIsDroppedThenInjectedRedirectedOnce()
    {
        var tracker = new FakeTracker();
        var nat = new NatTable();
        NatRedirectMiddleware middleware = Create(nat, tracker);
        var injector = new RecordingInjector();
        tracker.OnSweep = () => tracker.Track(Key(50000));  // the sweep finds the socket

        PacketContext ctx = Syn(50000, injector);
        bool passed = await InvokeAsync(middleware, ctx);

        Assert.False(passed);
        Assert.Equal(PacketDisposition.Drop, ctx.Disposition);

        (byte[] packet, WinDivertAddress address) = await injector.NextAsync();
        var p = PacketParser.Default.TryParse(packet, packet.Length)!;
        Assert.Equal(IPAddress.Loopback, p.Destination);
        Assert.Equal(RelayPort, p.DestinationPort);
        Assert.True(address.Loopback);
        Assert.Equal(1u, address.Network.IfIdx);

        NatEntry? entry = nat.Find(6, 50000, false);
        Assert.NotNull(entry);
        Assert.Equal(Remote, entry!.OriginalDestinationAddress);
        Assert.Equal(RemotePort, entry.OriginalDestinationPort);
        Assert.Equal(42u, entry.ProcessId);

        await Task.Delay(100);
        Assert.Equal(0, injector.Count);  // exactly one
    }

    [Fact]
    public async Task AnUntrackedSynTheSweepDoesNotFindIsInjectedUnchanged()
    {
        var tracker = new FakeTracker();
        var nat = new NatTable();
        var injector = new RecordingInjector();
        PacketContext ctx = Syn(50001, injector);
        byte[] original = ctx.Buffer[..ctx.Length];

        await InvokeAsync(Create(nat, tracker), ctx);

        Assert.Equal(PacketDisposition.Drop, ctx.Disposition);
        (byte[] packet, WinDivertAddress address) = await injector.NextAsync();
        Assert.Equal(original, packet);
        Assert.False(address.Loopback);
        Assert.True(address.Outbound);
        Assert.Null(nat.Find(6, 50001, false));
        Assert.Equal(1, tracker.Sweeps);
    }

    // The SOCKET pump records the flow while the sweep runs, so the sweep itself adds nothing.
    // Trusting that "nothing added" would lose the connection; the re-check must catch it.
    [Fact]
    public async Task AFlowRecordedDuringTheSweepIsStillRedirected()
    {
        var tracker = new FakeTracker { ReportsNothingAdded = true };
        tracker.OnSweep = () => tracker.Track(Key(50002));
        var nat = new NatTable();
        var injector = new RecordingInjector();

        await InvokeAsync(Create(nat, tracker), Syn(50002, injector));

        (byte[] packet, _) = await injector.NextAsync();
        Assert.Equal(RelayPort, PacketParser.Default.TryParse(packet, packet.Length)!.DestinationPort);
        Assert.NotNull(nat.Find(6, 50002, false));
    }

    [Fact]
    public async Task ConcurrentSynsShareSweeps()
    {
        var tracker = new FakeTracker { SweepDelay = TimeSpan.FromMilliseconds(50) };
        const int count = 50;
        tracker.OnSweep = () => { for (int i = 0; i < count; i++) tracker.Track(Key((ushort)(51000 + i))); };
        var nat = new NatTable();
        NatRedirectMiddleware middleware = Create(nat, tracker);
        var injector = new RecordingInjector();

        for (int i = 0; i < count; i++)
            await InvokeAsync(middleware, Syn((ushort)(51000 + i), injector));

        for (int i = 0; i < count; i++)
        {
            (byte[] packet, _) = await injector.NextAsync();
            Assert.Equal(RelayPort, PacketParser.Default.TryParse(packet, packet.Length)!.DestinationPort);
        }
        Assert.InRange(tracker.Sweeps, 1, 3);
        Assert.Equal(count, nat.Count);
    }

    [Fact]
    public async Task ARetransmittedSynWhileOneIsHeldIsDropped()
    {
        using var gate = new ManualResetEventSlim(false);
        var tracker = new FakeTracker { Gate = gate };
        tracker.OnSweep = () => tracker.Track(Key(50003));
        var injector = new RecordingInjector();
        NatRedirectMiddleware middleware = Create(new NatTable(), tracker);

        PacketContext first = Syn(50003, injector);
        PacketContext second = Syn(50003, injector);
        await InvokeAsync(middleware, first);
        await InvokeAsync(middleware, second);
        Assert.Equal(PacketDisposition.Drop, second.Disposition);

        gate.Set();
        await injector.NextAsync();
        await Task.Delay(150);
        Assert.Equal(0, injector.Count);
    }

    // The flow becomes tracked (SOCKET event) while its first SYN is held: a retransmission must
    // still be dropped, not rewritten on the pump next to the held copy.
    [Fact]
    public async Task ARetransmittedSynIsDroppedEvenOnceTheFlowIsTracked()
    {
        using var gate = new ManualResetEventSlim(false);
        var tracker = new FakeTracker { Gate = gate };
        var injector = new RecordingInjector();
        NatRedirectMiddleware middleware = Create(new NatTable(), tracker);

        await InvokeAsync(middleware, Syn(50006, injector));
        tracker.Track(Key(50006));
        PacketContext second = Syn(50006, injector);
        await InvokeAsync(middleware, second);
        Assert.Equal(PacketDisposition.Drop, second.Disposition);

        gate.Set();
        await injector.NextAsync();
        await Task.Delay(150);
        Assert.Equal(0, injector.Count);
    }

    [Fact]
    public async Task NothingIsInjectedAfterThePumpStops()
    {
        using var gate = new ManualResetEventSlim(false);
        var tracker = new FakeTracker { Gate = gate };
        tracker.OnSweep = () => tracker.Track(Key(50004));
        var injector = new RecordingInjector();
        using var cts = new CancellationTokenSource();

        await InvokeAsync(Create(new NatTable(), tracker), Syn(50004, injector, cts.Token));
        cts.Cancel();
        gate.Set();

        await Task.Delay(200);
        Assert.Equal(0, injector.Count);
    }

    // A tracked SYN stays on the synchronous path: rewritten in place, no sweep, no injection.
    [Fact]
    public async Task ATrackedSynIsRewrittenOnThePump()
    {
        var tracker = new FakeTracker();
        tracker.Track(Key(50005));
        var injector = new RecordingInjector();
        PacketContext ctx = Syn(50005, injector);

        await InvokeAsync(Create(new NatTable(), tracker), ctx);

        Assert.Equal(PacketDisposition.Modified, ctx.Disposition);
        Assert.Equal(0, tracker.Sweeps);
        Assert.Equal(0, injector.Count);
    }

    private static FlowKey Key(ushort localPort) => new FlowKey(6, Local, localPort, Remote, RemotePort);

    private static NatRedirectMiddleware Create(NatTable nat, FakeTracker tracker)
        => new NatRedirectMiddleware(
            nat, tracker, RelayPorts.Ipv4Only(RelayPort, 0), RedirectProtocol.Tcp, rootProcessId: 1,
            NullLogger<NatRedirectMiddleware>.Instance);

    private static async Task<bool> InvokeAsync(NatRedirectMiddleware middleware, PacketContext ctx)
    {
        bool passed = false;
        await middleware.InvokeAsync(ctx, _ => { passed = true; return Task.CompletedTask; });
        return passed;
    }

    // An outbound IPv4 SYN Local:localPort -> Remote:443 on a real interface.
    private static PacketContext Syn(ushort localPort, IPacketInjector injector, CancellationToken token = default)
    {
        byte[] packet = new byte[40];
        packet[0] = 0x45;
        packet[3] = 40;
        packet[8] = 64;
        packet[9] = 6;
        Local.GetAddressBytes().CopyTo(packet, 12);
        Remote.GetAddressBytes().CopyTo(packet, 16);
        packet[20] = (byte)(localPort >> 8);
        packet[21] = (byte)localPort;
        packet[22] = RemotePort >> 8;
        packet[23] = RemotePort & 0xFF;
        packet[27] = 1;        // seq
        packet[32] = 0x50;     // data offset 5
        packet[33] = 0x02;     // SYN
        packet[34] = 0xFF;     // window
        packet[35] = 0xFF;

        var ctx = new PacketContext(packet, injector, token)
        {
            Length = packet.Length,
            Packet = PacketParser.Default.TryParse(packet, packet.Length),
        };
        ctx.Address.Outbound = true;
        ctx.Address.Loopback = false;
        ctx.Address.Network.IfIdx = 7;
        return ctx;
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

    // Reconciles through the real CoalescedSweep, so the sweep count is what SocketTracker would do.
    private sealed class FakeTracker : ISocketTracker
    {
        private readonly ConcurrentDictionary<FlowKey, byte> _tracked = new();
        private readonly CoalescedSweep _sweep;
        private int _sweeps;

        public FakeTracker() { _sweep = new CoalescedSweep(Sweep); }

        public TimeSpan SweepDelay { get; init; }
        public ManualResetEventSlim? Gate { get; init; }
        public bool ReportsNothingAdded { get; init; }
        public Action? OnSweep { get; set; }
        public int Sweeps => Volatile.Read(ref _sweeps);

        public void Track(FlowKey key) => _tracked[key] = 0;

        private void Sweep()
        {
            Interlocked.Increment(ref _sweeps);
            Gate?.Wait(TimeSpan.FromSeconds(5));
            if (SweepDelay > TimeSpan.Zero) Thread.Sleep(SweepDelay);
            OnSweep?.Invoke();
        }

        public event Action<FlowKey>? TcpConnectEstablished { add { } remove { } }
        public event Action<FlowKey>? TcpConnectClosed { add { } remove { } }
        public event Action<IPAddress, ushort>? UdpBindAdded { add { } remove { } }
        public event Action<IPAddress, ushort>? UdpBindRemoved { add { } remove { } }

        public IReadOnlyCollection<uint> TrackedProcessIds => Array.Empty<uint>();
        public IReadOnlyCollection<FlowKey> TcpSnapshot => _tracked.Keys.ToArray();

        public void Start() { }
        public void AddProcess(uint pid) { }
        public bool RemoveProcess(uint pid) => false;
        public bool IsTrackedProcess(uint pid) => false;
        public bool IsTrackedTcp(FlowKey key) => _tracked.ContainsKey(key);
        public bool IsTrackedUdp(IPAddress localAddr, ushort localPort) => false;

        public bool TryGetTcpProcessId(FlowKey key, out uint processId)
        {
            processId = 42;
            return _tracked.ContainsKey(key);
        }

        public bool TryGetUdpProcessId(IPAddress localAddr, ushort localPort, out uint processId)
        {
            processId = 0;
            return false;
        }

        // The old synchronous path: one sweep per call, reporting what it found.
        public bool TryReconcileFromKernel(out int tcpAdded, out int udpAdded, bool force = false)
        {
            int before = _tracked.Count;
            Sweep();
            tcpAdded = ReportsNothingAdded ? 0 : _tracked.Count - before;
            udpAdded = 0;
            return tcpAdded > 0;
        }

        public Task ReconcileFromKernelAsync(CancellationToken cancellationToken = default)
            => _sweep.RequestAsync(cancellationToken);

        public void Dispose() { }
    }
}
