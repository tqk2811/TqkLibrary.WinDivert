using System;
using System.Threading;
using System.Threading.Tasks;

namespace TqkLibrary.WinDivert.Pipeline.Helpers;

/// <summary>
/// Runs a loop that spends its life blocked in a native call, on a thread of its own.
/// </summary>
/// <remarks>
/// Every pump in this library is such a loop: <c>WinDivertRecv</c> is a synchronous call that does
/// not return until the driver has something, so the thread running it is parked in the kernel for
/// as long as the pump lives. Started with <see cref="Task.Run(Action)"/> that thread is a
/// THREAD-POOL thread, and it is never given back.
/// <para>
/// That is affordable for one pump and ruinous for sixty. A redirector that follows a browser opens
/// a SOCKET handle per process — measured: 65 of them within a second of the engine starting, on a
/// 32-core machine — and each one takes a pool worker out of circulation for good. The pool starts
/// with one worker per core, so it is instantly short, and it replaces a missing worker at roughly
/// two a second. For the half-minute that takes, EVERYTHING else in the process that runs on the
/// pool waits behind the shortage: the relay's accept loop, every <c>await</c> continuation, every
/// timer callback. Measured on a real start: a VPN handshake whose round trips normally take ~75ms
/// took ~1000ms each, and connections took 270-890ms to reach the relay instead of under one — both
/// back to normal at about the 40-second mark, which is the pool finishing its catch-up. Worse than
/// slow: a handshake step whose reply arrives after its retransmit budget is spent fails outright,
/// which is how a dial that takes four seconds on a warm engine turned into a ninety-second one.
/// </para>
/// <para>
/// So these loops get their own threads. A blocked thread costs a stack and nothing else, and the
/// pool is left to the work it is for.
/// </para>
/// </remarks>
public static class BlockingLoop
{
    /// <summary>
    /// Starts <paramref name="loop"/> on a dedicated background thread and returns a task that
    /// completes when it returns — so callers can await or wait on it exactly as before.
    /// </summary>
    public static Task Start(Action loop)
    {
        if (loop is null) throw new ArgumentNullException(nameof(loop));

        // LongRunning is the documented way to ask the scheduler for a thread instead of a pool
        // worker, and it keeps the Task the existing teardown paths wait on.
        return Task.Factory.StartNew(
            loop, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
    }
}
