using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.WinDivert.Flow;
using TqkLibrary.WinDivert.Native;
using TqkLibrary.WinDivert.Packet;
using TqkLibrary.WinDivert.Redirect;

namespace TqkLibrary.WinDivert.Pipeline;

// Owns one WinDivert handle and its recv loop, and drives every captured packet through a
// composed middleware pipeline. Replaces the bespoke pump loops that used to live inside
// PacketInterceptor and Ipv6Blocker.
//
// Threading model: the recv loop runs the pipeline SYNCHRONOUSLY on the pump thread
// (GetAwaiter().GetResult()) so packets keep their recv order on this handle — essential for the
// NAT egress/reply path. Every built-in middleware completes synchronously; a middleware that
// needs slow async work (DNS-over-HTTPS) drops the original packet and finishes the work on a
// background task, re-injecting the result through IPacketInjector. So GetResult() never actually
// blocks on I/O.
public sealed class PacketPump : IPacketInjector, IDisposable
{
    private readonly string _tag;
    private readonly WinDivertHandle _handle;
    private readonly PacketDelegate _pipeline;
    private readonly SocketTracker _tracker;
    private readonly NatTable _nat;
    private readonly uint _pid;
    private readonly DnsCacheLookup? _dnsLookup;
    private readonly RedirectLogger _log;

    private readonly CancellationTokenSource _cts = new();
    private Task? _pumpTask;
    private volatile bool _disposed;

    public PacketPump(
        string tag,
        WinDivertHandle handle,
        PacketDelegate pipeline,
        SocketTracker tracker,
        NatTable nat,
        uint processId,
        DnsCacheLookup? dnsLookup,
        RedirectLogger? logger = null)
    {
        _tag = tag ?? throw new ArgumentNullException(nameof(tag));
        _handle = handle ?? throw new ArgumentNullException(nameof(handle));
        _pipeline = pipeline ?? throw new ArgumentNullException(nameof(pipeline));
        _tracker = tracker;
        _nat = nat;
        _pid = processId;
        _dnsLookup = dnsLookup;
        _log = logger ?? RedirectLogger.Null;
    }

    public void Start()
    {
        _pumpTask = Task.Run(() => PumpLoop(_cts.Token));
    }

    private void PumpLoop(CancellationToken ct)
    {
        byte[] buffer = new byte[65535];
        while (!ct.IsCancellationRequested)
        {
            if (!_handle.TryRecv(buffer, out int length, out WinDivertAddress addr))
                break;

            var ctx = new PacketContext(buffer, _tracker, _nat, _pid, _dnsLookup, this, _log, ct)
            {
                Length = length,
                Address = addr,
                Packet = PacketParser.TryParse(buffer, length),
            };

            try
            {
                _pipeline(ctx).GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                _log.Log(_tag, $"pipeline threw: {ex.GetType().Name}: {ex.Message}");
                ctx.Disposition = PacketDisposition.Pass;
            }

            if (ctx.Disposition == PacketDisposition.Drop)
                continue;

            if (ctx.Disposition == PacketDisposition.Modified)
                _handle.CalcChecksums(buffer, ctx.Length, ref ctx.Address);

            bool sent = _handle.TrySend(buffer, ctx.Length, ref ctx.Address);
            if (ctx.Disposition == PacketDisposition.Modified && !sent)
                _log.Log(_tag, $"  TrySend FAILED win32={Marshal.GetLastWin32Error()}");
        }
    }

    // Out-of-band injection (IPacketInjector). Safe to call from any thread; no-ops after dispose.
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
        _handle.Dispose();
        _cts.Dispose();
    }
}
