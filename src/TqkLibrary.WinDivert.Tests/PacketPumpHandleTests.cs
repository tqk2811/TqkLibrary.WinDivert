using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using TqkLibrary.WinDivert.Packet.Interfaces;
using TqkLibrary.WinDivert.Packet.Models;
using TqkLibrary.WinDivert.Pipeline;
using Xunit;

namespace TqkLibrary.WinDivert.Tests;

/// <summary>
/// Who is allowed to close a NETWORK handle. Same rule as <see cref="SocketTrackerHandleTests"/>:
/// the thread doing the reading closes it.
/// </summary>
public class PacketPumpHandleTests
{
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan SlowerThanTheDisposerWaits = TimeSpan.FromSeconds(2);

    private static PacketPump Pump(FakeWinDivertHandle handle)
        => new PacketPump(
            "test",
            handle,
            _ => Task.CompletedTask,
            new NoParser(),
            NullLogger<PacketPump>.Instance);

    // Dispose waited a second and then closed the handle regardless — on the reasoning, written
    // into a comment there, that a SafeHandle made it safe. It covers the call in flight and not
    // the one after, which is the one the pump was about to make.
    [Fact]
    public void A_pump_slower_than_Dispose_is_not_left_reading_a_closed_handle()
    {
        var handle = new FakeWinDivertHandle
        {
            LingerAfterStop = SlowerThanTheDisposerWaits,
            DeliversOneLastEvent = true,
        };
        PacketPump pump = Pump(handle);

        pump.Start();
        Assert.True(handle.WaitForFirstRecv(Patience), "the pump never reached its first recv");

        pump.Dispose();

        // The send, not the close: the close is what the buggy version does early, at the one
        // second mark, and this is the call it stranded.
        Assert.True(handle.WaitForSend(Patience), "the pump never re-injected its last packet");
        Assert.Equal(0, handle.UseAfterClose);
        Assert.True(handle.WaitUntilClosed(Patience), "nobody ever closed the handle");
    }

    // The handle now belongs to the pump loop, so a pump that never ran has to be the exception:
    // there is no loop to hand it to and Dispose has to close it itself.
    [Fact]
    public void A_pump_that_was_never_started_still_closes_its_handle()
    {
        var handle = new FakeWinDivertHandle();

        Pump(handle).Dispose();

        Assert.True(handle.IsClosed);
        Assert.Equal(0, handle.UseAfterClose);
    }

    private sealed class NoParser : IPacketParser
    {
        public ParsedPacket? TryParse(byte[] buffer, int length) => null;
    }
}
