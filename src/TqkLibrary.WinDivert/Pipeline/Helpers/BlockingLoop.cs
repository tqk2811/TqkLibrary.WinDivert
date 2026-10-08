using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

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
    /// <param name="latencyCritical">
    /// The loop releases packets the whole machine is waiting for (a NETWORK pump), so it is also
    /// registered with MMCSS — see <see cref="EnterMmcss"/>. Left false for the per-process SOCKET
    /// pumps: there are dozens of them and nothing waits on their events.
    /// </param>
    /// <param name="logger">Told when MMCSS refuses the thread; the loop runs either way.</param>
    public static Task Start(Action loop, bool latencyCritical = false, ILogger? logger = null)
    {
        if (loop is null) throw new ArgumentNullException(nameof(loop));

        // LongRunning is the documented way to ask the scheduler for a thread instead of a pool
        // worker, and it keeps the Task the existing teardown paths wait on.
        return Task.Factory.StartNew(
            () =>
            {
                // Every packet of the diverted traffic waits on this thread, so on a busy machine
                // it must not queue behind ordinary work. Highest is safe here because the loop
                // spends its life blocked in the driver, not spinning. The thread is ours alone
                // (LongRunning), so the priority does not leak into anything else.
                Thread.CurrentThread.Priority = ThreadPriority.Highest;
                IntPtr mmcss = latencyCritical ? EnterMmcss(logger) : IntPtr.Zero;
                try
                {
                    loop();
                }
                finally
                {
                    if (mmcss != IntPtr.Zero) AvRevertMmThreadCharacteristics(mmcss);
                }
            },
            CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
    }

    // Highest in a High-class process is priority 15: still level with every other High-class
    // thread on the machine, and below the realtime band, so on a busy machine the pump can wait
    // for a core while a game's packets sit in the driver. MMCSS is Windows' own answer for
    // threads with that problem (audio): it lifts the registered thread into the realtime band
    // (16-26) without making the whole process Realtime, and it keeps a share of every period for
    // ordinary threads (SystemResponsiveness, 20% by default), so a pump that ever did spin could
    // not freeze the machine. A pump spends its life blocked in the driver, far under that share.
    //
    // "Pro Audio" at High is the category meant for exactly this: short bursts of work that must
    // start the moment their input arrives.
    private static IntPtr EnterMmcss(ILogger? logger)
    {
        try
        {
            uint taskIndex = 0;
            IntPtr handle = AvSetMmThreadCharacteristicsW("Pro Audio", ref taskIndex);
            if (handle == IntPtr.Zero)
            {
                logger?.LogWarning("MMCSS refused the pump thread, win32={Win32}; it keeps its normal priority", Marshal.GetLastWin32Error());
                return IntPtr.Zero;
            }
            if (!AvSetMmThreadPriority(handle, AvrtPriorityHigh))
                logger?.LogDebug("MMCSS kept the pump thread at its default level, win32={Win32}", Marshal.GetLastWin32Error());
            return handle;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            logger?.LogWarning(ex, "MMCSS is not available; the pump thread keeps its normal priority");
            return IntPtr.Zero;
        }
    }

    private const int AvrtPriorityHigh = 1;

    [DllImport("avrt.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr AvSetMmThreadCharacteristicsW(string taskName, ref uint taskIndex);

    [DllImport("avrt.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AvSetMmThreadPriority(IntPtr avrtHandle, int priority);

    [DllImport("avrt.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AvRevertMmThreadCharacteristics(IntPtr avrtHandle);
}
