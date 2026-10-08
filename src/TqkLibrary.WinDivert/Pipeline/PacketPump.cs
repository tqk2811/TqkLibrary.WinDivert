using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TqkLibrary.WinDivert.Pipeline.Helpers;

namespace TqkLibrary.WinDivert.Pipeline;

/// <summary>
/// Owns one WinDivert handle and its recv loop, and drives every captured packet through a
/// composed middleware pipeline.
/// </summary>
/// <remarks>
/// Threading model: the recv loop runs the pipeline SYNCHRONOUSLY on the pump thread
/// (GetAwaiter().GetResult()) so packets keep their recv order on this handle — essential for the
/// NAT egress/reply path. Every built-in middleware completes synchronously; a middleware that
/// needs slow async work (DNS-over-HTTPS) drops the original packet and finishes the work on a
/// background task, re-injecting the result through <see cref="IPacketInjector"/>. So GetResult()
/// never actually blocks on I/O.
/// </remarks>
public sealed class PacketPump : IPacketPump
{
    private readonly IWinDivertHandle _handle;
    private readonly PacketDelegate _pipeline;
    private readonly IPacketParser _parser;
    private readonly ILogger _logger;
    private readonly IPacketBypass? _bypass;

    /// <summary>
    /// One byte over WINDIVERT_MTU_MAX (65575), the largest packet the driver will hand over.
    /// </summary>
    /// <remarks>
    /// A buffer that cannot hold the biggest packet does not truncate it — the driver refuses the
    /// call with ERROR_INSUFFICIENT_BUFFER. With segmentation offload on, packets that size are
    /// ordinary traffic, not a curiosity.
    /// </remarks>
    private const int RecvBufferSize = 65576;

    private const int ERROR_INSUFFICIENT_BUFFER = 122;
    private const int ERROR_NO_DATA = 232;
    private const int ERROR_OPERATION_ABORTED = 995;

    /// <summary>How many failed recvs in a row mean the handle is gone rather than unlucky.</summary>
    private const int MaxRecvFailuresInARow = 32;

    /// <summary>How often the capture-to-release latency of this pump is logged (Debug).</summary>
    private static readonly TimeSpan LatencyReportInterval = TimeSpan.FromSeconds(10);

    private readonly CancellationTokenSource _cts = new();
    private Task? _pumpTask;
    private volatile bool _started;
    private volatile bool _disposed;

    public string Name { get; }

    public event Action<PumpStop>? Stopped;

    /// <param name="name">Short label distinguishing this pump from the others in log lines.</param>
    /// <param name="handle">Taken over by the pump and disposed with it.</param>
    /// <param name="bypass">
    /// Optional fast path: packets it says the pipeline would not touch are re-sent as they came,
    /// skipping parse, context and pipeline. Null runs every packet through the pipeline.
    /// </param>
    public PacketPump(
        string name,
        IWinDivertHandle handle,
        PacketDelegate pipeline,
        IPacketParser parser,
        ILogger<PacketPump> logger,
        IPacketBypass? bypass = null)
    {
        _bypass = bypass;
        Name = name ?? throw new ArgumentNullException(nameof(name));
        _handle = handle ?? throw new ArgumentNullException(nameof(handle));
        _pipeline = pipeline ?? throw new ArgumentNullException(nameof(pipeline));
        _parser = parser ?? throw new ArgumentNullException(nameof(parser));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public void Start()
    {
        if (_started) throw new InvalidOperationException("Already started");
        // Set before the task exists, not after. Dispose reads it to decide who closes the handle,
        // and in the window between the pump being started and the assignment landing, a pump
        // would be reading a handle Dispose had already decided nobody owned.
        _started = true;
        // Latency-critical: every packet of the machine waits on this thread. See BlockingLoop.
        _pumpTask = BlockingLoop.Start(() => PumpLoop(_cts.Token), latencyCritical: true, _logger);
    }

    /// <summary>
    /// Runs the recv loop and closes the handle on the way out.
    /// </summary>
    /// <remarks>
    /// The close lives here because a <see cref="System.Runtime.InteropServices.SafeHandle"/>
    /// protects only the call in flight when another thread disposes it: the close waits for that
    /// call to return, but the next call throws ObjectDisposedException out of DangerousAddRef. A
    /// disposer that times out and closes anyway would leave this loop reading a dead handle.
    /// <see cref="Dispose"/> shuts the handle down — that is what makes the recv return — and waits;
    /// the close belongs to the thread doing the reading.
    /// </remarks>
    private void PumpLoop(CancellationToken ct)
    {
        try { Pump(ct); }
        finally { _handle.Dispose(); }
    }

    private void Pump(CancellationToken ct)
    {
        byte[] buffer = new byte[RecvBufferSize];
        int stopError = 0;
        int failuresInARow = 0;
        // Split by path, and for the full path also the pump's own work (recv returned → released),
        // so a slow window says whether packets queued behind the pump or the pipeline itself is slow.
        long statsStart = Stopwatch.GetTimestamp();
        var fastLatency = new PumpLatencyStats(LatencyReportInterval, statsStart);
        var fullLatency = new PumpLatencyStats(LatencyReportInterval, statsStart);
        var fullWork = new PumpLatencyStats(LatencyReportInterval, statsStart);
        bool logLatency = _logger.IsEnabled(LogLevel.Debug);
        while (!ct.IsCancellationRequested)
        {
            if (!_handle.TryRecv(buffer, out int length, out WinDivertAddress addr, out int win32))
            {
                // Being shut down is the only reason to leave on the first try. One packet the
                // buffer could not hold costs us that packet; any other error may well be
                // transient, and treating either as "stop" means silently passing every packet
                // from here on with nothing to say redirection has ended.
                if (win32 == ERROR_NO_DATA || win32 == ERROR_OPERATION_ABORTED) break;

                if (win32 == ERROR_INSUFFICIENT_BUFFER)
                    _logger.LogWarning("[{Pump}] a packet exceeded the {Size}-byte buffer and was skipped", Name, RecvBufferSize);
                else
                    _logger.LogError("[{Pump}] recv failed, win32={Win32}", Name, win32);

                // Persistent failure is a dead handle, and retrying it forever would spin a core
                // while claiming to redirect. Give up and say so.
                if (++failuresInARow >= MaxRecvFailuresInARow)
                {
                    stopError = win32;
                    _logger.LogError("[{Pump}] giving up after {Count} consecutive recv failures", Name, failuresInARow);
                    break;
                }
                continue;
            }

            failuresInARow = 0;
            long received = logLatency ? Stopwatch.GetTimestamp() : 0;

            // Fast path for traffic no stage would act on: released before anything is allocated,
            // so a busy machine's unrelated packets (a game's) do not queue behind our parsing.
            if (_bypass != null && ShouldBypass(buffer, length, addr))
            {
                long captured = addr.Timestamp;
                _handle.TrySend(buffer, length, ref addr);
                if (logLatency)
                {
                    fastLatency.Record(captured, Stopwatch.GetTimestamp());
                    ReportLatency(fastLatency, fullLatency, fullWork);
                }
                continue;
            }

            var ctx = new PacketContext(buffer, this, ct)
            {
                Length = length,
                Address = addr,
                Packet = _parser.TryParse(buffer, length),
            };

            try
            {
                _pipeline(ctx).GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[{Pump}] pipeline threw", Name);
                ctx.Disposition = PacketDisposition.Pass;
            }

            if (ctx.Disposition == PacketDisposition.Drop)
            {
                if (logLatency)
                {
                    fullWork.Record(received, Stopwatch.GetTimestamp());
                    ReportLatency(fastLatency, fullLatency, fullWork);
                }
                continue;
            }

            if (ctx.Disposition == PacketDisposition.Modified)
                _handle.CalcChecksums(buffer, ctx.Length, ref ctx.Address);

            bool sent = _handle.TrySend(buffer, ctx.Length, ref ctx.Address);
            if (ctx.Disposition == PacketDisposition.Modified && !sent)
                _logger.LogWarning("[{Pump}] send of a rewritten packet failed, win32={Win32}", Name, Marshal.GetLastWin32Error());

            if (logLatency)
            {
                long released = Stopwatch.GetTimestamp();
                fullLatency.Record(addr.Timestamp, released);
                fullWork.Record(received, released);
                ReportLatency(fastLatency, fullLatency, fullWork);
            }
        }

        if (stopError == 0) _logger.LogDebug("[{Pump}] pump loop exited", Name);
        try { Stopped?.Invoke(new PumpStop(Name, stopError)); }
        catch (Exception ex) { _logger.LogError(ex, "[{Pump}] a Stopped subscriber threw", Name); }
    }

    // A bypass that throws must not take the pump down; the packet just takes the normal path,
    // which is always correct.
    private bool ShouldBypass(byte[] buffer, int length, in WinDivertAddress addr)
    {
        try
        {
            return _bypass!.ShouldRelease(new ReadOnlySpan<byte>(buffer, 0, length), addr);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[{Pump}] bypass threw", Name);
            return false;
        }
    }

    // The three windows share their start, so they elapse together: the first one due decides.
    private void ReportLatency(PumpLatencyStats fast, PumpLatencyStats full, PumpLatencyStats work)
    {
        long now = Stopwatch.GetTimestamp();
        if (!fast.IsDue(now)) return;
        LogWindow("fast", fast.TryTakeSummary(now));
        LogWindow("full", full.TryTakeSummary(now));
        LogWindow("full-work", work.TryTakeSummary(now));
    }

    private void LogWindow(string path, PumpLatencySummary? summary)
    {
        if (summary is not PumpLatencySummary s) return;
        _logger.LogDebug("[{Pump}] capture-to-release {Path} over {Seconds:0}s: packets={Count} avg={Avg}us p50<={P50}us p99<={P99}us max={Max}us",
            Name, path, s.Window.TotalSeconds, s.Count, s.AverageMicros, s.P50Micros, s.P99Micros, s.MaxMicros);
    }

    /// <summary>
    /// Out-of-band injection. Safe to call from any thread; returns false rather than throwing
    /// once the pump has been disposed, so a late injection fails quietly.
    /// </summary>
    public bool Inject(byte[] buffer, int length, in WinDivertAddress addr)
    {
        if (_disposed) return false;
        WinDivertAddress local = addr;
        try
        {
            _handle.CalcChecksums(buffer, length, ref local);
            return _handle.TrySend(buffer, length, ref local);
        }
        catch
        {
            return false;
        }
    }

    public void Dispose()
    {
        _disposed = true;
        try { _cts.Cancel(); } catch { }
        try { _handle.Shutdown(); } catch { }

        if (_started)
        {
            // Best effort, and that is all it can be: a driver under load can hold a recv longer
            // than a second. When the wait does time out the handle closes a moment later, when the
            // pump leaves — not here. See PumpLoop for why closing it here was wrong.
            try { _pumpTask?.Wait(TimeSpan.FromSeconds(1)); } catch { }
        }
        else
        {
            // Never started, so there is no pump to hand it to.
            _handle.Dispose();
        }
        _cts.Dispose();
    }
}
