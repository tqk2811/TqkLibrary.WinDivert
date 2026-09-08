using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

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

    private readonly CancellationTokenSource _cts = new();
    private Task? _pumpTask;
    private volatile bool _disposed;

    public string Name { get; }

    public event Action<PumpStop>? Stopped;

    /// <param name="name">Short label distinguishing this pump from the others in log lines.</param>
    /// <param name="handle">Taken over by the pump and disposed with it.</param>
    public PacketPump(
        string name,
        IWinDivertHandle handle,
        PacketDelegate pipeline,
        IPacketParser parser,
        ILogger<PacketPump> logger)
    {
        Name = name ?? throw new ArgumentNullException(nameof(name));
        _handle = handle ?? throw new ArgumentNullException(nameof(handle));
        _pipeline = pipeline ?? throw new ArgumentNullException(nameof(pipeline));
        _parser = parser ?? throw new ArgumentNullException(nameof(parser));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public void Start()
    {
        if (_pumpTask != null) throw new InvalidOperationException("Already started");
        _pumpTask = Task.Run(() => PumpLoop(_cts.Token));
    }

    private void PumpLoop(CancellationToken ct)
    {
        byte[] buffer = new byte[RecvBufferSize];
        int stopError = 0;
        int failuresInARow = 0;
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
                continue;

            if (ctx.Disposition == PacketDisposition.Modified)
                _handle.CalcChecksums(buffer, ctx.Length, ref ctx.Address);

            bool sent = _handle.TrySend(buffer, ctx.Length, ref ctx.Address);
            if (ctx.Disposition == PacketDisposition.Modified && !sent)
                _logger.LogWarning("[{Pump}] send of a rewritten packet failed, win32={Win32}", Name, Marshal.GetLastWin32Error());
        }

        if (stopError == 0) _logger.LogDebug("[{Pump}] pump loop exited", Name);
        try { Stopped?.Invoke(new PumpStop(Name, stopError)); }
        catch (Exception ex) { _logger.LogError(ex, "[{Pump}] a Stopped subscriber threw", Name); }
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
        try { _pumpTask?.Wait(TimeSpan.FromSeconds(1)); } catch { }

        // The wait may time out — a driver under load can hold a recv longer than a second — and
        // disposing anyway is still safe: every call into the driver holds a reference on the
        // handle, so the close waits for the pump thread to come out rather than pulling the
        // handle out from under it.
        _handle.Dispose();
        _cts.Dispose();
    }
}
