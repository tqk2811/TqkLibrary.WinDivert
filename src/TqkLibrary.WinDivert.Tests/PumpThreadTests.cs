using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using TqkLibrary.WinDivert.Flow;
using TqkLibrary.WinDivert.Packet.Interfaces;
using TqkLibrary.WinDivert.Packet.Models;
using TqkLibrary.WinDivert.Pipeline;
using Xunit;

namespace TqkLibrary.WinDivert.Tests;

/// <summary>
/// Which thread a pump is allowed to run on.
/// </summary>
/// <remarks>
/// A pump spends its life inside a synchronous <c>WinDivertRecv</c>, so whatever thread it starts
/// on is a thread it never gives back. Started on the thread pool, one pump per tracked process is
/// a pool worker per tracked process — dozens for a browser — and the pool, which begins with one
/// worker per core and replaces a missing one at about two a second, is short for the half-minute
/// it takes to catch up. Everything else in the process that runs on the pool queues behind that:
/// on a real start it cost a VPN handshake ~1s per round trip instead of ~75ms, and connections
/// 270-890ms to reach the relay instead of under one.
/// </remarks>
public class PumpThreadTests
{
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(15);

    [Fact]
    public void A_packet_pump_does_not_run_on_a_thread_pool_thread()
    {
        var handle = new FakeWinDivertHandle(layer: Native.Enums.WinDivertLayer.Network);
        var pump = new PacketPump(
            "test", handle, _ => Task.CompletedTask, new NoParser(), NullLogger<PacketPump>.Instance);

        pump.Start();
        Assert.True(handle.WaitForFirstRecv(Patience), "the pump never reached its first recv");

        Assert.False(handle.FirstRecvOnThreadPoolThread);

        pump.Dispose();
    }

    [Fact]
    public void A_socket_pump_does_not_run_on_a_thread_pool_thread()
    {
        var handle = new FakeWinDivertHandle();
        var tracker = new SocketTracker(1234, new FakeHandleFactory(_ => handle), NullLogger<SocketTracker>.Instance);

        tracker.Start();
        Assert.True(handle.WaitForFirstRecv(Patience), "the pump never reached its first recv");

        Assert.False(handle.FirstRecvOnThreadPoolThread);

        tracker.Dispose();
    }

    /// <summary>The pipeline is not what these tests are about; nothing has to be parsed.</summary>
    private sealed class NoParser : IPacketParser
    {
        public ParsedPacket? TryParse(byte[] buffer, int length) => null;
    }
}
