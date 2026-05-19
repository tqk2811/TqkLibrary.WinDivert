using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.WinDivert.Native;
using TqkLibrary.WinDivert.Redirect;

namespace TqkLibrary.WinDivert.Flow;

internal readonly struct UdpBindKey : IEquatable<UdpBindKey>
{
    public IPAddress Address { get; }
    public ushort Port { get; }

    public UdpBindKey(IPAddress address, ushort port)
    {
        Address = address;
        Port = port;
    }

    public bool Equals(UdpBindKey other) => Port == other.Port && Equals(Address, other.Address);
    public override bool Equals(object? obj) => obj is UdpBindKey k && Equals(k);
    public override int GetHashCode() => (Address?.GetHashCode() ?? 0) ^ Port;
}

// Uses the SOCKET layer to learn which (localAddr:localPort, remoteAddr:remotePort) tuples
// belong to the target process. CONNECT events fire *before* the SYN is sent, giving the
// interceptor a chance to rewrite outbound packets from the very first one.
//
// Two reliability tricks layered on top of the raw event stream:
//   * Pre-populate from kernel TCP/UDP tables on Start() to cover sockets that existed
//     BEFORE the SOCKET filter attached.
//   * Reconcile from kernel tables on demand (throttled) — handles the race where the
//     Network-layer pump sees the SYN before the SOCKET-layer pump has added the FlowKey.
//   * Grace-period removal of TCP flows after SocketClose — kernel keeps retransmitting
//     trailing ACKs for several seconds after the process closes the socket, and those
//     packets would otherwise fall through and leak.
public sealed class SocketTracker : IDisposable
{
    // 0 = live; positive = TickCount at which the flow may be reaped.
    private readonly ConcurrentDictionary<FlowKey, long> _tcpFlows = new();
    private readonly ConcurrentDictionary<UdpBindKey, byte> _udpBinds = new();

    private readonly uint _processId;
    private readonly CancellationTokenSource _cts = new();
    private Task? _cleanupTask;

    // One WinDivert SOCKET handle per tracked pid. Each handle has its own pump task and writes
    // to the shared _tcpFlows / _udpBinds dictionaries. AddProcess opens a new handle on demand
    // so child processes spawned by the root target can be followed without reopening anything.
    private readonly ConcurrentDictionary<uint, PerPidHandle> _pidHandles = new();

    private sealed class PerPidHandle
    {
        public WinDivertHandle Handle { get; }
        public Task PumpTask { get; }
        public PerPidHandle(WinDivertHandle h, Task t) { Handle = h; PumpTask = t; }
    }

    // Linger window before a closed TCP flow is purged. Kernel typically retransmits the
    // trailing FIN-ACK / RST-ACK for up to ~tcp_max_retries seconds; 30s is conservative.
    private const int TcpCloseGraceMs = 30_000;
    // Cleanup pass period.
    private const int CleanupIntervalMs = 5_000;
    // Minimum gap between full kernel-table reconciliations on the hot path.
    private const int ReconcileMinIntervalMs = 50;

    private int _lastReconcileTicks;

    public event Action<FlowKey>? TcpConnectEstablished;
    public event Action<FlowKey>? TcpConnectClosed;
    public event Action<IPAddress, ushort>? UdpBindAdded;
    public event Action<IPAddress, ushort>? UdpBindRemoved;

    public SocketTracker(uint processId)
    {
        _processId = processId;
        _lastReconcileTicks = Environment.TickCount - ReconcileMinIntervalMs;
    }

    public bool IsTrackedTcp(FlowKey key) => _tcpFlows.ContainsKey(key);

    public bool IsTrackedUdp(IPAddress localAddr, ushort localPort)
    {
        if (_udpBinds.ContainsKey(new UdpBindKey(localAddr, localPort))) return true;
        // BIND on ANY (0.0.0.0 / ::) accepts any source address at that port.
        if (_udpBinds.ContainsKey(new UdpBindKey(IPAddress.Any, localPort))) return true;
        if (_udpBinds.ContainsKey(new UdpBindKey(IPAddress.IPv6Any, localPort))) return true;
        return false;
    }

    public IReadOnlyCollection<FlowKey> TcpSnapshot => (IReadOnlyCollection<FlowKey>)_tcpFlows.Keys;

    public IReadOnlyCollection<uint> TrackedProcessIds => (IReadOnlyCollection<uint>)_pidHandles.Keys;

    public void Start()
    {
        if (_pidHandles.Count > 0) throw new InvalidOperationException("Already started");
        AddProcess(_processId);
        _cleanupTask = Task.Run(() => CleanupLoop(_cts.Token));
    }

    // Adds a new pid to the tracked set. Opens a dedicated WinDivert SOCKET handle scoped to that
    // pid and spawns a pump task; subsequent socket events for the pid flow into the shared
    // _tcpFlows / _udpBinds. Safe to call after Start() — used by ProcessTreeMonitor when a child
    // process is detected.
    public void AddProcess(uint pid)
    {
        if (_cts.IsCancellationRequested) return;
        if (_pidHandles.ContainsKey(pid)) return;

        string filter = $"processId == {pid} and (tcp or udp)";
        DiagnosticLogger.Log("TRK", $"AddProcess pid={pid} filter=\"{filter}\"");
        WinDivertHandle handle;
        try
        {
            handle = WinDivertHandle.Open(
                filter,
                WinDivertLayer.Socket,
                priority: 0,
                flags: WinDivertOpenFlags.Sniff | WinDivertOpenFlags.RecvOnly);
        }
        catch (Exception ex)
        {
            DiagnosticLogger.Log("TRK", $"AddProcess pid={pid} OPEN FAILED: {ex.GetType().Name}: {ex.Message}");
            return;
        }
        Task pumpTask = Task.Run(() => PumpLoop(handle, pid, _cts.Token));
        var entry = new PerPidHandle(handle, pumpTask);
        if (!_pidHandles.TryAdd(pid, entry))
        {
            // race with another AddProcess for the same pid — discard ours
            try { handle.Shutdown(); } catch { }
            handle.Dispose();
            return;
        }

        // Pre-populate this pid's existing sockets so events that fired before the filter
        // attached are not lost (mirrors the root-pid behaviour at Start time).
        PrePopulateForPid(pid);
    }

    private void PrePopulateForPid(uint pid)
    {
        int tcpAdded = 0, udpAdded = 0;
        try
        {
            foreach (var f in IpHlpApi.EnumerateProcessTcpFlows(pid))
            {
                var key = new FlowKey(6, f.LocalAddr, f.LocalPort, f.RemoteAddr, f.RemotePort);
                if (_tcpFlows.TryAdd(key, 0L))
                {
                    tcpAdded++;
                    TcpConnectEstablished?.Invoke(key);
                }
            }
            foreach (var b in IpHlpApi.EnumerateProcessUdpBinds(pid))
            {
                if (_udpBinds.TryAdd(new UdpBindKey(b.LocalAddr, b.LocalPort), 1))
                {
                    udpAdded++;
                    UdpBindAdded?.Invoke(b.LocalAddr, b.LocalPort);
                }
            }
        }
        catch (Exception ex)
        {
            DiagnosticLogger.Log("TRK", $"PrePopulate pid={pid} failed: {ex.GetType().Name}: {ex.Message}");
        }
        DiagnosticLogger.Log("TRK", $"PrePopulate pid={pid} done tcpAdded={tcpAdded} udpAdded={udpAdded}");
    }

    // Snapshot the kernel's TCP/UDP tables for every tracked pid and add anything new. Used by
    // PacketInterceptor when an egress packet doesn't match a known flow — covers the race where
    // the SYN reaches the Network layer before SocketConnect has been processed.
    //
    // Throttled so a flood of unmatched packets doesn't trigger a snapshot per packet.
    internal bool TryReconcileFromKernel(out int tcpAdded, out int udpAdded)
    {
        tcpAdded = 0;
        udpAdded = 0;
        int now = Environment.TickCount;
        int prev = Volatile.Read(ref _lastReconcileTicks);
        // Unchecked subtraction is safe across TickCount wrap (results in a small negative).
        if (now - prev < ReconcileMinIntervalMs) return false;
        if (Interlocked.CompareExchange(ref _lastReconcileTicks, now, prev) != prev) return false;

        try
        {
            foreach (uint pid in _pidHandles.Keys)
            {
                foreach (var f in IpHlpApi.EnumerateProcessTcpFlows(pid))
                {
                    var key = new FlowKey(6, f.LocalAddr, f.LocalPort, f.RemoteAddr, f.RemotePort);
                    if (_tcpFlows.TryAdd(key, 0L))
                    {
                        tcpAdded++;
                        TcpConnectEstablished?.Invoke(key);
                    }
                }
                foreach (var b in IpHlpApi.EnumerateProcessUdpBinds(pid))
                {
                    if (_udpBinds.TryAdd(new UdpBindKey(b.LocalAddr, b.LocalPort), 1))
                    {
                        udpAdded++;
                        UdpBindAdded?.Invoke(b.LocalAddr, b.LocalPort);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            DiagnosticLogger.Log("TRK", $"Reconcile failed: {ex.GetType().Name}: {ex.Message}");
            return false;
        }
        if (tcpAdded > 0 || udpAdded > 0)
            DiagnosticLogger.Log("TRK", $"Reconcile added tcp={tcpAdded} udp={udpAdded}");
        return tcpAdded > 0 || udpAdded > 0;
    }

    private void PumpLoop(WinDivertHandle handle, uint pid, CancellationToken ct)
    {
        byte[] dummy = new byte[0];
        while (!ct.IsCancellationRequested)
        {
            if (!handle.TryRecv(dummy, out _, out WinDivertAddress addr))
                break;
            HandleEvent(addr);
        }
        DiagnosticLogger.Log("TRK", $"PumpLoop pid={pid} exited");
    }

    private async Task CleanupLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { await Task.Delay(CleanupIntervalMs, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }

            int now = Environment.TickCount;
            int reaped = 0;
            foreach (var kv in _tcpFlows)
            {
                long expireTick = kv.Value;
                if (expireTick == 0) continue;
                // (int)(now - expireTick) handles TickCount wrap correctly via two's-complement.
                if ((int)(now - (int)expireTick) >= 0)
                {
                    if (_tcpFlows.TryRemove(kv.Key, out _)) reaped++;
                }
            }
            if (reaped > 0)
                DiagnosticLogger.Log("TRK", $"Cleanup reaped tcp={reaped} remaining={_tcpFlows.Count}");
        }
    }

    private void HandleEvent(WinDivertAddress addr)
    {
        if (addr.Layer != WinDivertLayer.Socket) return;
        bool isIpv6 = addr.IPv6;
        var data = addr.Socket;
        IPAddress local = data.GetLocalAddress(isIpv6);
        IPAddress remote = data.GetRemoteAddress(isIpv6);
        ushort lp = data.LocalPort;
        ushort rp = data.RemotePort;
        byte proto = data.Protocol;

        DiagnosticLogger.Log("TRK", $"evt={addr.Event} proto={proto} pid={data.ProcessId} {local}:{lp} -> {remote}:{rp}");

        switch (addr.Event)
        {
            case WinDivertEvent.SocketConnect:
                if (proto == 6)
                {
                    var key = new FlowKey(proto, local, lp, remote, rp);
                    // (Re-)mark as live: clear any pending expiry from a previous close.
                    bool added = _tcpFlows.TryAdd(key, 0L);
                    if (!added) _tcpFlows[key] = 0L;
                    DiagnosticLogger.Log("TRK", $"  tcpFlows.add={added} count={_tcpFlows.Count} key={key}");
                    if (added) TcpConnectEstablished?.Invoke(key);
                }
                break;

            case WinDivertEvent.SocketClose:
                if (proto == 6)
                {
                    var key = new FlowKey(proto, local, lp, remote, rp);
                    // Don't remove immediately — kernel still retransmits trailing FIN/ACK packets
                    // for several seconds. Mark with an expiry tick; the cleanup task purges later.
                    long expireAt = Environment.TickCount + TcpCloseGraceMs;
                    bool wasLive = _tcpFlows.TryGetValue(key, out long current) && current == 0;
                    _tcpFlows[key] = expireAt;
                    DiagnosticLogger.Log("TRK", $"  tcpFlows.markClose wasLive={wasLive} graceMs={TcpCloseGraceMs} count={_tcpFlows.Count} key={key}");
                    if (wasLive) TcpConnectClosed?.Invoke(key);
                }
                else if (proto == 17)
                {
                    if (_udpBinds.TryRemove(new UdpBindKey(local, lp), out _))
                        UdpBindRemoved?.Invoke(local, lp);
                }
                break;

            case WinDivertEvent.SocketBind:
                if (proto == 17)
                {
                    if (_udpBinds.TryAdd(new UdpBindKey(local, lp), 1))
                        UdpBindAdded?.Invoke(local, lp);
                }
                break;
        }
    }

    public void Dispose()
    {
        try { _cts.Cancel(); } catch { }
        foreach (var kv in _pidHandles)
        {
            try { kv.Value.Handle.Shutdown(); } catch { }
        }
        foreach (var kv in _pidHandles)
        {
            try { kv.Value.PumpTask.Wait(TimeSpan.FromSeconds(1)); } catch { }
            kv.Value.Handle.Dispose();
        }
        _pidHandles.Clear();
        try { _cleanupTask?.Wait(TimeSpan.FromSeconds(1)); } catch { }
        _cts.Dispose();
    }
}
