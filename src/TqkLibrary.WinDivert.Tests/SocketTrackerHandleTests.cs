using System;
using System.Threading;
using Microsoft.Extensions.Logging.Abstractions;
using TqkLibrary.WinDivert.Flow;
using Xunit;

namespace TqkLibrary.WinDivert.Tests;

/// <summary>
/// Who is allowed to close a SOCKET handle.
/// </summary>
/// <remarks>
/// A SafeHandle protects the call that is in flight when another thread disposes it — the close
/// waits for that call to return — but not the call after, which throws ObjectDisposedException out
/// of DangerousAddRef. Every disposer here used to close the handle whether or not the pump reading
/// it had left, so the pump's next call threw on a thread-pool thread nobody was watching. The rule
/// these tests hold to is that the thread doing the reading is the one that closes.
/// </remarks>
public class SocketTrackerHandleTests
{
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(15);

    // Longer than the second a disposer is willing to wait, which a driver under load really can be.
    private static readonly TimeSpan SlowerThanTheDisposerWaits = TimeSpan.FromSeconds(2);

    private static NullLogger<SocketTracker> Log => NullLogger<SocketTracker>.Instance;

    [Fact]
    public void A_pump_slower_than_Dispose_is_not_left_reading_a_closed_handle()
    {
        var handle = new FakeWinDivertHandle
        {
            LingerAfterStop = SlowerThanTheDisposerWaits,
            DeliversOneLastEvent = true,
        };
        var tracker = new SocketTracker(1234, new FakeHandleFactory(_ => handle), Log);

        tracker.Start();
        Assert.True(handle.WaitForFirstRecv(Patience), "the pump never reached its first recv");

        // Gives up on the pump after a second — and used to close the handle at that point anyway.
        tracker.Dispose();

        // Waiting for the send, not for the close. The close is what the buggy version does early;
        // the call that pays for it is this one, a second later, when the slow recv returns.
        Assert.True(handle.WaitForSend(Patience), "the pump never made its call after the shutdown");
        Assert.Equal(0, handle.UseAfterClose);
        Assert.True(handle.WaitUntilClosed(Patience), "nobody ever closed the handle");
    }

    [Fact]
    public void A_pump_slower_than_RemoveProcess_is_not_left_reading_a_closed_handle()
    {
        var handle = new FakeWinDivertHandle
        {
            LingerAfterStop = SlowerThanTheDisposerWaits,
            DeliversOneLastEvent = true,
        };
        var tracker = new SocketTracker(0, new FakeHandleFactory(_ => handle), Log);

        try
        {
            tracker.Start();
            tracker.AddProcess(4321);
            Assert.True(handle.WaitForFirstRecv(Patience), "the pump never reached its first recv");

            Assert.True(tracker.RemoveProcess(4321));

            Assert.True(handle.WaitForSend(Patience), "the pump never made its call after the shutdown");
            Assert.Equal(0, handle.UseAfterClose);
            Assert.True(handle.WaitUntilClosed(Patience), "nobody ever closed the handle");
        }
        finally
        {
            tracker.Dispose();
        }
    }

    // The one that was actually crashing. Two threads add the same pid; the loser has already
    // started a pump on the handle it opened, and nothing ever waits for that task — so closing the
    // handle on the spot meant the pump's own recv threw where no one could see it.
    [Fact]
    public void A_handle_discarded_after_losing_the_add_race_is_closed_by_its_own_pump()
    {
        const uint pid = 4321;
        SocketTracker? tracker = null;
        FakeWinDivertHandle? discarded = null;
        int reentered = 0;

        // Re-entering from inside Open is what makes the race a certainty rather than a coin toss:
        // the inner call publishes its entry for the pid while the outer call is still holding the
        // handle it opened, so the outer TryAdd is guaranteed to lose.
        var factory = new FakeHandleFactory(filter =>
        {
            var handle = new FakeWinDivertHandle(filter) { StreamsEvents = true };
            if (Interlocked.Exchange(ref reentered, 1) == 0)
            {
                tracker!.AddProcess(pid);
                discarded = handle;
            }
            return handle;
        });

        tracker = new SocketTracker(0, factory, Log);
        try
        {
            tracker.AddProcess(pid);

            Assert.NotNull(discarded);
            Assert.True(discarded!.WaitForFirstRecv(Patience), "the discarded pump never ran");
            Assert.True(discarded.WaitUntilClosed(Patience), "the discarded handle was never closed");
            Assert.Equal(0, discarded.UseAfterClose);
        }
        finally
        {
            tracker.Dispose();
        }
    }

    // A pump that gives up on a failing handle used to leave its entry in the table: the pid still
    // read as tracked, and AddProcess saw the entry and never opened a new handle.
    [Fact]
    public void A_pump_that_gives_up_drops_its_pid_and_says_so()
    {
        const uint pid = 4321;
        const int ErrorAccessDenied = 5;
        var factory = new FakeHandleFactory(filter => new FakeWinDivertHandle(filter) { FailsEveryRecvWith = ErrorAccessDenied });
        var tracker = new SocketTracker(0, factory, Log);
        using var stopped = new ManualResetEventSlim(false);
        uint stoppedPid = 0;
        tracker.ProcessPumpStopped += p => { stoppedPid = p; stopped.Set(); };

        try
        {
            tracker.AddProcess(pid);

            Assert.True(stopped.Wait(Patience), "ProcessPumpStopped never fired");
            Assert.Equal(pid, stoppedPid);
            Assert.True(SpinWait.SpinUntil(() => !tracker.IsTrackedProcess(pid), Patience), "the pid still reads as tracked");

            tracker.AddProcess(pid);
            Assert.Equal(2, factory.Opened.Count);
        }
        finally
        {
            tracker.Dispose();
        }
    }

    // A pump of an old handle that gives up after the pid was removed and added again must not report:
    // the pid is tracked by the new handle, and the event would make the host treat it as lost.
    [Fact]
    public void A_stale_pump_giving_up_after_the_pid_was_added_again_says_nothing()
    {
        const uint pid = 4321;
        const int ErrorAccessDenied = 5;
        using var gate = new ManualResetEventSlim(false);
        FakeWinDivertHandle? first = null;
        var factory = new FakeHandleFactory(filter =>
        {
            if (first is null)
                return first = new FakeWinDivertHandle(filter) { FailsEveryRecvWith = ErrorAccessDenied, FailsOnlyOnceSet = gate };
            return new FakeWinDivertHandle(filter);
        });
        var tracker = new SocketTracker(0, factory, Log);
        int stoppedCount = 0;
        tracker.ProcessPumpStopped += _ => Interlocked.Increment(ref stoppedCount);

        try
        {
            tracker.AddProcess(pid);
            Assert.True(first!.WaitForFirstRecv(Patience));
            Assert.True(tracker.RemoveProcess(pid));
            tracker.AddProcess(pid);
            Assert.Equal(2, factory.Opened.Count);

            gate.Set();
            Assert.True(first.WaitUntilClosed(Patience), "the stale pump never gave up");

            Assert.Equal(0, Volatile.Read(ref stoppedCount));
            Assert.True(tracker.IsTrackedProcess(pid));
        }
        finally
        {
            tracker.Dispose();
        }
    }
}
