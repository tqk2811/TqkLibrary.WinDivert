using System.Net;
using TqkLibrary.WinDivert.Flow.Models;
using TqkLibrary.WinDivert.Flow.Interfaces;
using TqkLibrary.WinDivert.Redirect;
using TqkLibrary.WinDivert.Redirect.Models;
using Xunit;

namespace TqkLibrary.WinDivert.Tests;

/// <summary>
/// A flow the tracker reports closed stops answering for its source port once the grace window
/// has run out, for TCP and UDP alike (backlog B3).
/// </summary>
public class NatTableExpiryTests
{
    private const int GraceMs = 30_000;
    private static readonly IPAddress Local = IPAddress.Parse("192.168.1.20");
    private static readonly IPAddress Remote = IPAddress.Parse("93.184.216.34");

    private long _now = 1_000_000;

    private NatTable CreateWired(out EventTracker tracker)
    {
        var nat = new NatTable(() => _now);
        tracker = new EventTracker();
        ProcessRedirector.WireNatExpiry(tracker, nat);
        return nat;
    }

    private static NatEntry Entry(byte protocol, IPAddress src, ushort srcPort, IPAddress dst)
        => new NatEntry(42, protocol, src, srcPort, dst, 443, 1, 0);

    [Fact]
    public void ClosedTcpFlowStaysFindableForTheGraceThenExpires()
    {
        NatTable nat = CreateWired(out EventTracker tracker);
        nat.Upsert(Entry(6, Local, 50000, Remote));

        tracker.RaiseTcpClosed(new FlowKey(6, Local, 50000, Remote, 443));

        _now += GraceMs - 1;
        Assert.NotNull(nat.Find(6, 50000, isIpv6: false));
        _now += 1;
        Assert.Null(nat.Find(6, 50000, isIpv6: false));
    }

    [Fact]
    public void RemovedUdpBindExpiresItsEntry()
    {
        NatTable nat = CreateWired(out EventTracker tracker);
        nat.Upsert(Entry(17, Local, 50001, Remote));

        tracker.RaiseUdpRemoved(Local, 50001);

        _now += GraceMs - 1;
        Assert.NotNull(nat.Find(17, 50001, isIpv6: false));
        _now += 1;
        Assert.Null(nat.Find(17, 50001, isIpv6: false));
    }

    [Fact]
    public void RemovedIpv6UdpBindExpiresOnlyTheIpv6Entry()
    {
        NatTable nat = CreateWired(out EventTracker tracker);
        IPAddress local6 = IPAddress.Parse("fe80::1");
        IPAddress remote6 = IPAddress.Parse("2001:db8::1");
        nat.Upsert(Entry(17, local6, 50002, remote6));
        nat.Upsert(Entry(17, Local, 50002, Remote));

        tracker.RaiseUdpRemoved(local6, 50002);
        _now += GraceMs;

        Assert.Null(nat.Find(17, 50002, isIpv6: true));
        Assert.NotNull(nat.Find(17, 50002, isIpv6: false));
    }

    [Fact]
    public void RemovedDualStackUdpBindExpiresBothFamilies()
    {
        NatTable nat = CreateWired(out EventTracker tracker);
        nat.Upsert(Entry(17, IPAddress.Parse("fe80::1"), 50003, IPAddress.Parse("2001:db8::1")));
        nat.Upsert(Entry(17, Local, 50003, Remote));

        tracker.RaiseUdpRemoved(IPAddress.IPv6Any, 50003);
        _now += GraceMs;

        Assert.Null(nat.Find(17, 50003, isIpv6: true));
        Assert.Null(nat.Find(17, 50003, isIpv6: false));
    }

    [Fact]
    public void UdpCloseDoesNotTouchTheTcpEntryOnTheSamePort()
    {
        NatTable nat = CreateWired(out EventTracker tracker);
        nat.Upsert(Entry(6, Local, 50004, Remote));

        tracker.RaiseUdpRemoved(Local, 50004);
        _now += GraceMs;

        Assert.NotNull(nat.Find(6, 50004, isIpv6: false));
    }

    /// <summary>Only the two close events are live; everything else is inert.</summary>
    private sealed class EventTracker : ISocketTracker
    {
        public event Action<FlowKey>? TcpConnectClosed;
        public event Action<IPAddress, ushort>? UdpBindRemoved;
        public event Action<FlowKey>? TcpConnectEstablished { add { } remove { } }
        public event Action<IPAddress, ushort>? UdpBindAdded { add { } remove { } }

        public void RaiseTcpClosed(FlowKey key) => TcpConnectClosed?.Invoke(key);
        public void RaiseUdpRemoved(IPAddress address, ushort port) => UdpBindRemoved?.Invoke(address, port);

        public IReadOnlyCollection<uint> TrackedProcessIds => Array.Empty<uint>();
        public IReadOnlyCollection<FlowKey> TcpSnapshot => Array.Empty<FlowKey>();
        public void Start() { }
        public void AddProcess(uint pid) { }
        public bool RemoveProcess(uint pid) => false;
        public bool IsTrackedProcess(uint pid) => false;
        public bool IsTrackedTcp(FlowKey key) => false;
        public bool IsTrackedUdp(IPAddress localAddr, ushort localPort) => false;
        public bool TryGetTcpProcessId(FlowKey key, out uint processId) { processId = 0; return false; }
        public bool TryGetUdpProcessId(IPAddress localAddr, ushort localPort, out uint processId) { processId = 0; return false; }
        public bool TryReconcileFromKernel(out int tcpAdded, out int udpAdded, bool force = false) { tcpAdded = udpAdded = 0; return false; }
        public void Dispose() { }
    }
}
