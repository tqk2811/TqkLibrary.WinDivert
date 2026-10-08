using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using TqkLibrary.WinDivert.Flow.Interfaces;
using TqkLibrary.WinDivert.Flow.Models;
using TqkLibrary.WinDivert.Native.Enums;
using TqkLibrary.WinDivert.Native.Interfaces;
using TqkLibrary.WinDivert.Native.Models;
using TqkLibrary.WinDivert.Packet;
using TqkLibrary.WinDivert.Pipeline;
using TqkLibrary.WinDivert.Pipeline.Interfaces;
using TqkLibrary.WinDivert.Redirect;
using TqkLibrary.WinDivert.Redirect.Enums;
using TqkLibrary.WinDivert.Redirect.Models;
using Xunit;

namespace TqkLibrary.WinDivert.Tests;

/// <summary>
/// The redirect pump's fast path: only untracked, non-SYN, non-DNS egress on a real interface is
/// released without the pipeline, and the reconcile NAT would have asked for is still asked for.
/// </summary>
public class UntrackedEgressBypassTests
{
    private const ushort LocalPort = 50000;
    private const ushort RemotePort = 443;
    private static readonly IPAddress Local = IPAddress.Parse("192.168.1.20");
    private static readonly IPAddress Remote = IPAddress.Parse("93.184.216.34");
    private static readonly IPAddress Local6 = IPAddress.Parse("2001:db8::20");
    private static readonly IPAddress Remote6 = IPAddress.Parse("2001:db8::1");

    private const byte TcpAck = 0x10;
    private const byte TcpSyn = 0x02;

    [Fact]
    public void Untracked_outbound_tcp_ack_is_released_and_still_requests_a_reconcile()
    {
        var tracker = new FakeTracker();
        Assert.True(Release(Bypass(tracker), Tcp(TcpAck), Outbound()));
        Assert.Equal(1, tracker.BackgroundRequests);
    }

    [Fact]
    public void Untracked_outbound_udp_is_released()
    {
        var tracker = new FakeTracker();
        Assert.True(Release(Bypass(tracker, RedirectProtocol.Tcp | RedirectProtocol.Udp), Udp(LocalPort, RemotePort), Outbound()));
        Assert.Equal(1, tracker.BackgroundRequests);
    }

    // NAT never reaches its untracked branch for a protocol it does not redirect, so neither may
    // the bypass ask for a reconcile there.
    [Fact]
    public void Udp_when_only_tcp_is_redirected_is_released_without_a_reconcile()
    {
        var tracker = new FakeTracker();
        Assert.True(Release(Bypass(tracker, RedirectProtocol.Tcp), Udp(LocalPort, RemotePort), Outbound()));
        Assert.Equal(0, tracker.BackgroundRequests);
    }

    [Fact]
    public void Untracked_outbound_ipv6_tcp_ack_is_released()
    {
        var bypass = new UntrackedEgressBypass(new FakeTracker(), RelayPorts.Ipv6Only(5001, 0), RedirectProtocol.Tcp);
        Assert.True(Release(bypass, Tcp6(nextHeader: 6), Outbound()));
    }

    [Fact]
    public void Syn_is_not_released()
        => Assert.False(Release(Bypass(new FakeTracker()), Tcp(TcpSyn), Outbound()));

    [Fact]
    public void Syn_ack_is_released()
        => Assert.True(Release(Bypass(new FakeTracker()), Tcp(TcpSyn | TcpAck), Outbound()));

    [Fact]
    public void Tracked_tcp_flow_is_not_released()
    {
        var tracker = new FakeTracker();
        tracker.TrackTcp(new FlowKey(6, Local, LocalPort, Remote, RemotePort));
        Assert.False(Release(Bypass(tracker), Tcp(TcpAck), Outbound()));
    }

    // Tracked UDP is what BlockTargetUdpMiddleware drops, even when NAT does not redirect UDP.
    [Fact]
    public void Tracked_udp_bind_is_not_released()
    {
        var tracker = new FakeTracker();
        tracker.TrackUdp(LocalPort);
        Assert.False(Release(Bypass(tracker, RedirectProtocol.Tcp), Udp(LocalPort, RemotePort), Outbound()));
    }

    // The SOCKET pump can record the flow between the first lookup and the reconcile request.
    [Fact]
    public void A_flow_that_becomes_tracked_on_the_recheck_is_not_released()
    {
        var tracker = new FakeTracker();
        tracker.OnRequest = () => tracker.TrackTcp(new FlowKey(6, Local, LocalPort, Remote, RemotePort));
        Assert.False(Release(Bypass(tracker), Tcp(TcpAck), Outbound()));
    }

    [Theory]
    [InlineData(53, 40000)]
    [InlineData(40000, 53)]
    public void Dns_port_in_either_direction_is_not_released(int srcPort, int dstPort)
    {
        var bypass = Bypass(new FakeTracker(), RedirectProtocol.Tcp | RedirectProtocol.Udp);
        Assert.False(Release(bypass, Udp((ushort)srcPort, (ushort)dstPort), Outbound()));
        Assert.False(Release(bypass, Tcp(TcpAck, (ushort)srcPort, (ushort)dstPort), Outbound()));
    }

    [Fact]
    public void Loopback_is_not_released()
    {
        WinDivertAddress addr = Outbound();
        addr.Loopback = true;
        Assert.False(Release(Bypass(new FakeTracker()), Tcp(TcpAck), addr));
    }

    [Fact]
    public void Inbound_is_not_released()
        => Assert.False(Release(Bypass(new FakeTracker()), Tcp(TcpAck), default));

    [Theory]
    [InlineData(0x20, 0x00)]   // more fragments
    [InlineData(0x00, 0x10)]   // offset != 0
    public void Ipv4_fragment_is_not_released(byte flagsHigh, byte offsetLow)
    {
        byte[] packet = Tcp(TcpAck);
        packet[6] = flagsHigh;
        packet[7] = offsetLow;
        Assert.False(Release(Bypass(new FakeTracker()), packet, Outbound()));
    }

    [Fact]
    public void Truncated_packet_is_not_released()
    {
        byte[] packet = Tcp(TcpAck);
        var bypass = Bypass(new FakeTracker());
        // Cut inside the TCP header (before the flags byte), inside the IP header, and to nothing.
        Assert.False(bypass.ShouldRelease(packet.AsSpan(0, 30), Outbound()));
        Assert.False(bypass.ShouldRelease(packet.AsSpan(0, 12), Outbound()));
        Assert.False(bypass.ShouldRelease(ReadOnlySpan<byte>.Empty, Outbound()));
    }

    [Fact]
    public void Ipv6_with_an_extension_header_is_not_released()
    {
        var bypass = new UntrackedEgressBypass(new FakeTracker(), RelayPorts.Ipv6Only(5001, 0), RedirectProtocol.Tcp);
        Assert.False(Release(bypass, Tcp6(nextHeader: 0), Outbound()));   // hop-by-hop
    }

    // ---- the pump side ----

    [Fact]
    public void A_released_packet_is_sent_without_running_the_pipeline()
    {
        var (sends, pipelineRuns) = RunPump(Tcp(TcpAck), bypassAnswer: true);
        Assert.Equal(1, sends);
        Assert.Equal(0, pipelineRuns);
    }

    [Fact]
    public void A_packet_the_bypass_declines_runs_the_pipeline()
    {
        var (sends, pipelineRuns) = RunPump(Tcp(TcpAck), bypassAnswer: false);
        Assert.Equal(1, sends);
        Assert.Equal(1, pipelineRuns);
    }

    private static (int Sends, int PipelineRuns) RunPump(byte[] packet, bool bypassAnswer)
    {
        var handle = new OnePacketHandle(packet, Outbound());
        int pipelineRuns = 0;
        var pump = new PacketPump(
            "test", handle,
            _ => { Interlocked.Increment(ref pipelineRuns); return Task.CompletedTask; },
            PacketParser.Default,
            NullLogger<PacketPump>.Instance,
            new FixedBypass(bypassAnswer));
        using var stopped = new ManualResetEventSlim();
        pump.Stopped += _ => stopped.Set();
        pump.Start();
        Assert.True(stopped.Wait(TimeSpan.FromSeconds(10)), "the pump never finished its one packet");
        pump.Dispose();
        return (handle.Sends, Volatile.Read(ref pipelineRuns));
    }

    // ---- builders ----

    private static UntrackedEgressBypass Bypass(FakeTracker tracker, RedirectProtocol protocols = RedirectProtocol.Tcp)
        => new UntrackedEgressBypass(tracker, RelayPorts.Ipv4Only(5000, 5002), protocols);

    private static bool Release(UntrackedEgressBypass bypass, byte[] packet, WinDivertAddress addr)
        => bypass.ShouldRelease(packet, addr);

    private static WinDivertAddress Outbound()
    {
        WinDivertAddress addr = default;
        addr.Outbound = true;
        addr.Loopback = false;
        return addr;
    }

    private static byte[] Tcp(byte flags, ushort srcPort = LocalPort, ushort dstPort = RemotePort)
    {
        byte[] p = Ipv4(protocol: 6, totalLength: 40);
        Ports(p, 20, srcPort, dstPort);
        p[32] = 0x50;          // data offset 5
        p[33] = flags;
        return p;
    }

    private static byte[] Udp(ushort srcPort, ushort dstPort)
    {
        byte[] p = Ipv4(protocol: 17, totalLength: 28);
        Ports(p, 20, srcPort, dstPort);
        p[25] = 8;             // udp length
        return p;
    }

    private static byte[] Ipv4(byte protocol, int totalLength)
    {
        byte[] p = new byte[totalLength];
        p[0] = 0x45;
        p[3] = (byte)totalLength;
        p[8] = 64;
        p[9] = protocol;
        Local.GetAddressBytes().CopyTo(p, 12);
        Remote.GetAddressBytes().CopyTo(p, 16);
        return p;
    }

    private static byte[] Tcp6(byte nextHeader)
    {
        byte[] p = new byte[60];
        p[0] = 0x60;
        p[5] = 20;             // payload length
        p[6] = nextHeader;
        p[7] = 64;
        Local6.GetAddressBytes().CopyTo(p, 8);
        Remote6.GetAddressBytes().CopyTo(p, 24);
        Ports(p, 40, LocalPort, RemotePort);
        p[52] = 0x50;
        p[53] = TcpAck;
        return p;
    }

    private static void Ports(byte[] p, int offset, ushort src, ushort dst)
    {
        p[offset] = (byte)(src >> 8);
        p[offset + 1] = (byte)src;
        p[offset + 2] = (byte)(dst >> 8);
        p[offset + 3] = (byte)dst;
    }

    // ---- fakes ----

    private sealed class FixedBypass : IPacketBypass
    {
        private readonly bool _answer;
        public FixedBypass(bool answer) { _answer = answer; }
        public bool ShouldRelease(ReadOnlySpan<byte> packet, in WinDivertAddress address) => _answer;
    }

    // Hands the pump one packet, then reports the handle shut down.
    private sealed class OnePacketHandle : IWinDivertHandle
    {
        private const int ErrorNoData = 232;
        private readonly byte[] _packet;
        private readonly WinDivertAddress _addr;
        private int _delivered;
        private int _sends;

        public OnePacketHandle(byte[] packet, WinDivertAddress addr)
        {
            _packet = packet;
            _addr = addr;
        }

        public int Sends => Volatile.Read(ref _sends);
        public WinDivertLayer Layer => WinDivertLayer.Network;
        public string Filter => "true";

        public bool TryRecv(byte[] buffer, out int length, out WinDivertAddress addr, out int win32Error)
        {
            if (Interlocked.Exchange(ref _delivered, 1) == 0)
            {
                _packet.CopyTo(buffer, 0);
                length = _packet.Length;
                addr = _addr;
                win32Error = 0;
                return true;
            }
            length = 0;
            addr = default;
            win32Error = ErrorNoData;
            return false;
        }

        public bool TrySend(byte[] buffer, int length, ref WinDivertAddress addr)
        {
            Interlocked.Increment(ref _sends);
            return true;
        }

        public void CalcChecksums(byte[] buffer, int length, ref WinDivertAddress addr, WinDivertChecksumFlags flags = WinDivertChecksumFlags.All) { }
        public void SetParam(WinDivertParam param, ulong value) { }
        public ulong GetParam(WinDivertParam param) => 0;
        public void Shutdown(WinDivertShutdown how = WinDivertShutdown.Both) { }
        public void Dispose() { }
    }

    private sealed class FakeTracker : ISocketTracker
    {
        private readonly ConcurrentDictionary<FlowKey, byte> _tcp = new();
        private readonly ConcurrentDictionary<ushort, byte> _udp = new();
        private int _backgroundRequests;

        public Action? OnRequest { get; set; }
        public int BackgroundRequests => Volatile.Read(ref _backgroundRequests);

        public void TrackTcp(FlowKey key) => _tcp[key] = 0;
        public void TrackUdp(ushort port) => _udp[port] = 0;

        public event Action<FlowKey>? TcpConnectEstablished { add { } remove { } }
        public event Action<FlowKey>? TcpConnectClosed { add { } remove { } }
        public event Action<IPAddress, ushort>? UdpBindAdded { add { } remove { } }
        public event Action<IPAddress, ushort>? UdpBindRemoved { add { } remove { } }

        public IReadOnlyCollection<uint> TrackedProcessIds => Array.Empty<uint>();
        public IReadOnlyCollection<FlowKey> TcpSnapshot => _tcp.Keys.ToArray();

        public void Start() { }
        public void AddProcess(uint pid) { }
        public bool RemoveProcess(uint pid) => false;
        public bool IsTrackedProcess(uint pid) => false;
        public bool IsTrackedTcp(FlowKey key) => _tcp.ContainsKey(key);
        public bool IsTrackedUdp(IPAddress localAddr, ushort localPort) => _udp.ContainsKey(localPort);

        public bool TryGetTcpProcessId(FlowKey key, out uint processId)
        {
            processId = 0;
            return false;
        }

        public bool TryGetUdpProcessId(IPAddress localAddr, ushort localPort, out uint processId)
        {
            processId = 0;
            return false;
        }

        public bool TryReconcileFromKernel(out int tcpAdded, out int udpAdded, bool force = false)
        {
            tcpAdded = 0;
            udpAdded = 0;
            return false;
        }

        public void RequestReconcileFromKernel()
        {
            Interlocked.Increment(ref _backgroundRequests);
            OnRequest?.Invoke();
        }

        public void Dispose() { }
    }
}
