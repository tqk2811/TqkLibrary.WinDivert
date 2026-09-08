using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.WinDivert.Native;
using Microsoft.Extensions.Logging;

namespace TqkLibrary.WinDivert.Flow;

// Uses the SOCKET layer to learn which (localAddr:localPort, remoteAddr:remotePort) tuples
// belong to the tracked processes. CONNECT events fire *before* the SYN is sent, giving the
// interceptor a chance to rewrite outbound packets from the very first one.
//
// Every flow records the pid that owns it, so a tracker following several processes can tell the
// NAT stage which process a packet really came from (per-process routing policies).
//
// Two reliability tricks layered on top of the raw event stream:
//   * Pre-populate from kernel TCP/UDP tables on Start() to cover sockets that existed
//     BEFORE the SOCKET filter attached.
//   * Reconcile from kernel tables on demand (throttled) — handles the race where the
//     Network-layer pump sees the SYN before the SOCKET-layer pump has added the FlowKey.
//   * Grace-period removal of TCP flows after SocketClose — kernel keeps retransmitting
//     trailing ACKs for several seconds after the process closes the socket, and those
//     packets would otherwise fall through and leak.
//
// Two ways of deciding whose events matter, chosen by the caller:
//   * one SOCKET handle per pid, filtered in the driver ("processId == N"). Nothing is heard about
//     a process until something else — a process watcher — has named it, so a process is only
//     followed from the moment that watcher noticed it.
//   * one SOCKET handle for the whole machine, with a callback deciding pid by pid. The event
//     itself carries the pid, so a process is judged the instant it opens a socket rather than
//     when it started; the answer is cached so the callback is asked once per process.
public sealed class SocketTracker : ISocketTracker
{
    private readonly ConcurrentDictionary<FlowKey, TcpFlowState> _tcpFlows = new();
    private readonly ConcurrentDictionary<UdpBindKey, UdpBindState> _udpBinds = new();

    private readonly uint _processId;
    private readonly short _socketPriority;
    // Null for per-pid handles. Non-null puts this tracker in machine-wide mode: it answers
    // "should this process be redirected?" for a pid nobody has mentioned before. Null BACK from
    // it means "cannot tell yet" — the process table has not caught up — and is deliberately not
    // cached, so the next event for that pid asks again instead of writing it off forever.
    private readonly Func<uint, bool?>? _shouldTrackProcess;
    private readonly IWinDivertHandleFactory _handleFactory;
    private readonly ILogger<SocketTracker> _logger;
    private readonly CancellationTokenSource _cts = new();
    private Task? _cleanupTask;
    private bool _started;

    // One WinDivert SOCKET handle per tracked pid. Each handle has its own pump task and writes
    // to the shared _tcpFlows / _udpBinds dictionaries. AddProcess opens a new handle on demand
    // so child processes spawned by the root target can be followed without reopening anything.
    private readonly ConcurrentDictionary<uint, PerPidHandle> _pidHandles = new();

    // Machine-wide mode only: what the callback answered about each pid. This is also the tracked
    // set — there is no per-pid handle to stand in for it.
    private readonly ConcurrentDictionary<uint, bool> _pidDecisions = new();

    // Machine-wide mode only: the single SOCKET handle every process's events arrive on.
    private PerPidHandle? _allHandle;

    private sealed class PerPidHandle
    {
        public IWinDivertHandle Handle { get; }
        public Task PumpTask { get; }

        public PerPidHandle(IWinDivertHandle h, Task t)
        {
            Handle = h;
            PumpTask = t;
        }
    }

    // Linger window before a closed TCP flow is purged. Kernel typically retransmits the
    // trailing FIN-ACK / RST-ACK for up to ~tcp_max_retries seconds; 30s is conservative.
    private const int TcpCloseGraceMs = 30_000;
    // Cleanup pass period.
    private const int CleanupIntervalMs = 5_000;
    // Minimum gap between full kernel-table reconciliations on the hot path.
    private const int ReconcileMinIntervalMs = 50;

    private const int ERROR_NO_DATA = 232;
    private const int ERROR_OPERATION_ABORTED = 995;
    // How many failed recvs in a row mean the handle is gone rather than unlucky.
    private const int MaxRecvFailuresInARow = 32;

    private int _lastReconcileTicks;

    // Cached so the per-sweep predicate does not allocate a delegate on the packet path.
    private readonly Func<uint, bool> _isTrackedPid;

    public event Action<FlowKey>? TcpConnectEstablished;
    public event Action<FlowKey>? TcpConnectClosed;
    public event Action<IPAddress, ushort>? UdpBindAdded;
    public event Action<IPAddress, ushort>? UdpBindRemoved;

    /// <param name="processId">
    /// Root process to follow. Zero means "start with nothing tracked" — pids are then added via
    /// <see cref="AddProcess"/> as a process watcher discovers them. Ignored in machine-wide mode,
    /// where the callback decides.
    /// </param>
    /// <param name="shouldTrackProcess">
    /// Machine-wide mode: asked once per pid, on the pump thread, the first time that process is
    /// seen opening a socket. True redirects it, false leaves it alone, and null means "not yet
    /// known" — nothing is remembered and the question is asked again on its next event. Null for
    /// the whole parameter keeps the per-pid handles instead.
    /// </param>
    public SocketTracker(
        uint processId,
        IWinDivertHandleFactory handleFactory,
        ILogger<SocketTracker> logger,
        short socketPriority = 0,
        Func<uint, bool?>? shouldTrackProcess = null)
    {
        _processId = processId;
        _socketPriority = socketPriority;
        _shouldTrackProcess = shouldTrackProcess;
        _handleFactory = handleFactory ?? throw new ArgumentNullException(nameof(handleFactory));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _lastReconcileTicks = Environment.TickCount - ReconcileMinIntervalMs;
        _isTrackedPid = shouldTrackProcess is null ? _pidHandles.ContainsKey : IsAcceptedPid;
    }

    /// <summary>True when this tracker listens to the whole machine and judges pid by pid.</summary>
    private bool IsMachineWide => _shouldTrackProcess != null;

    public bool IsTrackedTcp(FlowKey key) => _tcpFlows.ContainsKey(key);

    public bool IsTrackedUdp(IPAddress localAddr, ushort localPort)
        => TryGetUdpProcessId(localAddr, localPort, out _);

    // Owner of a tracked TCP flow. False when the flow is unknown.
    public bool TryGetTcpProcessId(FlowKey key, out uint processId)
    {
        if (_tcpFlows.TryGetValue(key, out TcpFlowState? state))
        {
            processId = state.ProcessId;
            return true;
        }
        processId = 0;
        return false;
    }

    // Owner of a tracked UDP bind. A bind on ANY (0.0.0.0 / ::) accepts any source address at
    // that port, so it is checked as a fallback.
    public bool TryGetUdpProcessId(IPAddress localAddr, ushort localPort, out uint processId)
    {
        if (_udpBinds.TryGetValue(new UdpBindKey(localAddr, localPort), out UdpBindState? state)
            || _udpBinds.TryGetValue(new UdpBindKey(IPAddress.Any, localPort), out state)
            || _udpBinds.TryGetValue(new UdpBindKey(IPAddress.IPv6Any, localPort), out state))
        {
            processId = state.ProcessId;
            return true;
        }
        processId = 0;
        return false;
    }

    public IReadOnlyCollection<FlowKey> TcpSnapshot => (IReadOnlyCollection<FlowKey>)_tcpFlows.Keys;

    public IReadOnlyCollection<uint> TrackedProcessIds
        => IsMachineWide
            ? _pidDecisions.Where(kv => kv.Value).Select(kv => kv.Key).ToArray()
            : (IReadOnlyCollection<uint>)_pidHandles.Keys;

    public void Start()
    {
        if (_started) throw new InvalidOperationException("Already started");
        _started = true;
        if (IsMachineWide) OpenMachineWideHandle();
        else if (_processId != 0) AddProcess(_processId);
        _cleanupTask = Task.Run(() => CleanupLoop(_cts.Token));
    }

    // One handle for every process on the machine. The filter cannot name the pids we want —
    // that is the whole point, we do not know them yet — so it takes every socket event and the
    // decision moves to HandleEvent. Sniffing for the same reason as the per-pid handles: the
    // SOCKET layer offers nothing else (see AddProcess).
    private void OpenMachineWideHandle()
    {
        const string filter = "tcp or udp";
        _logger.LogDebug("opening a machine-wide SOCKET handle, filter={Filter}", filter);

        IWinDivertHandle handle;
        try
        {
            handle = _handleFactory.Open(
                filter,
                WinDivertLayer.Socket,
                priority: _socketPriority,
                flags: WinDivertOpenFlags.Sniff | WinDivertOpenFlags.RecvOnly);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "no machine-wide SOCKET handle (win32={Win32}) — nothing will be tracked",
                (ex as System.ComponentModel.Win32Exception)?.NativeErrorCode);
            return;
        }

        _allHandle = new PerPidHandle(handle, Task.Run(() => PumpLoop(handle, 0, _cts.Token)));
    }

    // The verdict on one pid, asked once and then remembered. "Not yet known" is not remembered:
    // it usually means the process table has not caught up with a process that was created
    // moments ago, and writing it off would lose that process for as long as it runs.
    private bool AcceptPid(uint pid)
    {
        if (_pidDecisions.TryGetValue(pid, out bool known)) return known;

        bool? verdict;
        try { verdict = _shouldTrackProcess!(pid); }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "deciding whether pid={Pid} should be tracked failed", pid);
            return false;
        }

        if (verdict is null) return false;

        _pidDecisions[pid] = verdict.Value;
        if (verdict.Value)
        {
            _logger.LogDebug("pid={Pid} is now tracked, decided from its own socket event", pid);
            // The event that got us here is one socket; the process may have had others open long
            // before this handle existed, and those produce no event ever again. The kernel's own
            // tables are where they are, so they are read once, here, at the moment the process
            // becomes ours — exactly what AddProcess does for a pid named from outside.
            PrePopulateForPid(pid);
        }
        return verdict.Value;
    }

    private bool IsAcceptedPid(uint pid) => _pidDecisions.TryGetValue(pid, out bool ok) && ok;

    // Adds a new pid to the tracked set. Opens a dedicated WinDivert SOCKET handle scoped to that
    // pid and spawns a pump task; subsequent socket events for the pid flow into the shared
    // _tcpFlows / _udpBinds. Safe to call after Start() — used by ProcessTreeMonitor when a child
    // process is detected.
    public void AddProcess(uint pid)
    {
        if (_cts.IsCancellationRequested) return;

        // Machine-wide mode has no handle to open — the events are already arriving. Being told
        // about a pid here is a caller (a suspended launch, a process the user picked) settling
        // the verdict in advance, so the pump never has to ask.
        if (IsMachineWide)
        {
            if (_pidDecisions.TryGetValue(pid, out bool already) && already) return;
            _pidDecisions[pid] = true;
            PrePopulateForPid(pid);
            return;
        }

        if (_pidHandles.ContainsKey(pid)) return;

        string filter = $"processId == {pid} and (tcp or udp)";
        _logger.LogDebug("AddProcess pid={Pid} filter={Filter}", pid, filter);
        IWinDivertHandle handle;
        // Always sniffing, and it has to be. The SOCKET layer is the one place where the two
        // WinDivert flags fight each other:
        //
        //   * RECV_ONLY is mandatory — WinDivertOpen refuses a SOCKET handle without it and
        //     returns ERROR_INVALID_PARAMETER (87), which reads like a bad filter expression.
        //   * Without SNIFF the handle is a FILTER, not an observer: the driver holds each socket
        //     operation and only lets it proceed when the event is re-injected. RECV_ONLY makes
        //     that re-injection impossible, so nothing ever proceeds.
        //
        // Opening RECV_ONLY alone therefore succeeds and then silently blocks every connect() of
        // every tracked process — measured: a browser with no network at all, six redirected
        // packets in five minutes, not one connection reaching the relay. So sniffing is not a
        // fallback here, it is the only mode this layer offers us.
        //
        // The cost is a race the tracker cannot win on its own: the socket event may still be in
        // flight when the SYN reaches the NETWORK layer. That is what the kernel-table reconcile
        // in TryReconcileFromKernel is for.
        try
        {
            handle = _handleFactory.Open(
                filter,
                WinDivertLayer.Socket,
                priority: _socketPriority,
                flags: WinDivertOpenFlags.Sniff | WinDivertOpenFlags.RecvOnly);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "AddProcess pid={Pid}: no SOCKET handle (win32={Win32}) — this process will not be tracked", pid, (ex as System.ComponentModel.Win32Exception)?.NativeErrorCode);
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

    // Removes a pid from the tracked set: closes its SOCKET handle and forgets every flow/bind
    // that belongs to it, so a process the user un-selects stops being redirected without tearing
    // down the whole redirector. Unknown pid = no-op.
    //
    // Flows are dropped immediately (no linger): the caller asked to stop touching this process,
    // so trailing packets should reach the kernel unmodified rather than keep hitting the relay.
    public bool RemoveProcess(uint pid)
    {
        if (IsMachineWide)
        {
            // The pid is forgotten rather than remembered as "no": a pid the caller drops is
            // usually a process that has exited, and Windows hands its number to something else
            // soon enough. A remembered "no" would then be answering about the wrong program.
            if (!_pidDecisions.TryRemove(pid, out bool wasTracked)) return false;
            if (!wasTracked) return false;
        }
        else if (!_pidHandles.TryRemove(pid, out PerPidHandle? entry)) return false;
        else
        {
            _logger.LogDebug("RemoveProcess pid={Pid}", pid);
            try { entry.Handle.Shutdown(); } catch { }
            try { entry.PumpTask.Wait(TimeSpan.FromSeconds(1)); } catch { }
            entry.Handle.Dispose();
        }

        int tcpRemoved = 0, udpRemoved = 0;
        foreach (var kv in _tcpFlows)
        {
            if (kv.Value.ProcessId != pid) continue;
            if (_tcpFlows.TryRemove(kv.Key, out _))
            {
                tcpRemoved++;
                TcpConnectClosed?.Invoke(kv.Key);
            }
        }
        foreach (var kv in _udpBinds)
        {
            if (kv.Value.ProcessId != pid) continue;
            if (_udpBinds.TryRemove(kv.Key, out _))
            {
                udpRemoved++;
                UdpBindRemoved?.Invoke(kv.Key.Address, kv.Key.Port);
            }
        }
        _logger.LogDebug("RemoveProcess pid={Pid} done, tcpRemoved={TcpRemoved} udpRemoved={UdpRemoved}", pid, tcpRemoved, udpRemoved);
        return true;
    }

    public bool IsTrackedProcess(uint pid)
        => IsMachineWide ? IsAcceptedPid(pid) : _pidHandles.ContainsKey(pid);

    private void PrePopulateForPid(uint pid)
    {
        int tcpAdded = 0, udpAdded = 0;
        try
        {
            IpHlpApi.SnapshotTcpFlows(p => p == pid, (p, f) => { if (RecordTcp(p, f)) tcpAdded++; });
            IpHlpApi.SnapshotUdpBinds(p => p == pid, (p, b) => { if (RecordUdp(p, b)) udpAdded++; });
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "PrePopulate pid={Pid} failed", pid);
        }
        _logger.LogDebug("PrePopulate pid={Pid} done, tcpAdded={TcpAdded} udpAdded={UdpAdded}", pid, tcpAdded, udpAdded);
    }

    // The two "add it if it is new" halves shared by pre-populate and reconcile. Both report
    // whether the row was actually new, which is the only thing either caller counts.
    private bool RecordTcp(uint pid, IpHlpApi.TcpFlow flow)
    {
        var key = new FlowKey(6, flow.LocalAddr, flow.LocalPort, flow.RemoteAddr, flow.RemotePort);
        if (!_tcpFlows.TryAdd(key, new TcpFlowState(pid))) return false;
        TcpConnectEstablished?.Invoke(key);
        return true;
    }

    private bool RecordUdp(uint pid, IpHlpApi.UdpBind bind)
    {
        if (!_udpBinds.TryAdd(new UdpBindKey(bind.LocalAddr, bind.LocalPort), new UdpBindState(pid))) return false;
        UdpBindAdded?.Invoke(bind.LocalAddr, bind.LocalPort);
        return true;
    }

    // Snapshot the kernel's TCP/UDP tables for every tracked pid and add anything new. Used by
    // NatRedirectMiddleware when an egress packet doesn't match a known flow — covers the race
    // where the SYN reaches the Network layer before SocketConnect has been processed.
    //
    // Throttled so a flood of unmatched packets doesn't trigger a snapshot per packet.
    // force skips the throttle. The caller passes it for a SYN, where the answer decides whether
    // a brand-new connection is captured or lost: connect() has already put the socket in the
    // kernel table by the time the SYN reaches the NETWORK layer, so this lookup is what closes
    // the race the sniffing SOCKET handle cannot — and the SOCKET layer gives us no handle that
    // could close it on its own (see AddProcess), so this stays on the SYN path for good.
    //
    // What makes that affordable is the shape of the sweep below: four kernel-table reads for the
    // whole tracked set, not four per tracked pid.
    public bool TryReconcileFromKernel(out int tcpAdded, out int udpAdded, bool force = false)
    {
        tcpAdded = 0;
        udpAdded = 0;
        int now = Environment.TickCount;
        int prev = Volatile.Read(ref _lastReconcileTicks);
        if (!force)
        {
            // Unchecked subtraction is safe across TickCount wrap (results in a small negative).
            if (now - prev < ReconcileMinIntervalMs) return false;
            if (Interlocked.CompareExchange(ref _lastReconcileTicks, now, prev) != prev) return false;
        }
        else
        {
            Volatile.Write(ref _lastReconcileTicks, now);
        }

        // ONE sweep of each kernel table for the whole tracked set. Reading them per pid meant
        // 4 machine-wide table reads times the number of tracked processes — with a browser that
        // is dozens of pids, i.e. hundreds of reads, per SYN, on the pump thread.
        int tcp = 0, udp = 0;
        try
        {
            IpHlpApi.SnapshotTcpFlows(_isTrackedPid, (pid, f) => { if (RecordTcp(pid, f)) tcp++; });
            IpHlpApi.SnapshotUdpBinds(_isTrackedPid, (pid, b) => { if (RecordUdp(pid, b)) udp++; });
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Reconcile from the kernel tables failed");
            return false;
        }
        tcpAdded = tcp;
        udpAdded = udp;
        if (tcpAdded > 0 || udpAdded > 0)
            _logger.LogDebug("Reconcile added tcp={TcpAdded} udp={UdpAdded}", tcpAdded, udpAdded);
        return tcpAdded > 0 || udpAdded > 0;
    }

    private void PumpLoop(IWinDivertHandle handle, uint pid, CancellationToken ct)
    {
        byte[] dummy = new byte[0];
        int failuresInARow = 0;
        while (!ct.IsCancellationRequested)
        {
            if (!handle.TryRecv(dummy, out _, out WinDivertAddress addr, out int win32))
            {
                // Same reasoning as the packet pump: only a shutdown means stop. Giving up on any
                // error would leave this process untracked with nothing to say so.
                if (win32 == ERROR_NO_DATA || win32 == ERROR_OPERATION_ABORTED) break;
                _logger.LogWarning("Socket event recv for pid={Pid} failed, win32={Win32}", pid, win32);
                if (++failuresInARow >= MaxRecvFailuresInARow)
                {
                    _logger.LogError("Socket pump for pid={Pid} giving up after {Count} consecutive failures", pid, failuresInARow);
                    break;
                }
                continue;
            }
            failuresInARow = 0;

            try
            {
                HandleEvent(addr);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Socket event for pid={Pid} could not be recorded", pid);
            }
            finally
            {
                // Harmless on a sniffing handle (the send simply fails) but kept deliberately: it
                // is what would release the socket operation if this handle were ever opened in
                // filter mode. See AddProcess for why it is not.
                handle.TrySend(dummy, 0, ref addr);
            }
        }
        _logger.LogDebug("Socket pump for pid={Pid} exited (0 = machine-wide)", pid);
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
                long expireTick = kv.Value.ExpireTick;
                if (expireTick == 0) continue;
                // (int)(now - expireTick) handles TickCount wrap correctly via two's-complement.
                if ((int)(now - (int)expireTick) >= 0)
                {
                    if (_tcpFlows.TryRemove(kv.Key, out _)) reaped++;
                }
            }
            if (reaped > 0)
                _logger.LogDebug("Cleanup reaped {Reaped} closed TCP flow(s), {Remaining} remaining", reaped, _tcpFlows.Count);
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
        uint pid = data.ProcessId;

        // Machine-wide mode hears every process on the machine, so this is where everything that
        // is not ours is dropped — before a flow is recorded, and before anything is logged about
        // it at trace level.
        if (IsMachineWide && !AcceptPid(pid)) return;

        _logger.LogTrace("evt={Event} proto={Protocol} pid={Pid} {Local}:{LocalPort} -> {Remote}:{RemotePort}", addr.Event, proto, pid, local, lp, remote, rp);

        switch (addr.Event)
        {
            case WinDivertEvent.SocketConnect:
                if (proto == 6)
                {
                    var key = new FlowKey(proto, local, lp, remote, rp);
                    // (Re-)mark as live: clear any pending expiry from a previous close.
                    var state = new TcpFlowState(pid);
                    bool added = _tcpFlows.TryAdd(key, state);
                    if (!added) _tcpFlows[key] = state;
                    _logger.LogTrace("  tcp flow added={Added} count={Count} key={Key}", added, _tcpFlows.Count, key);
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
                    bool wasLive = _tcpFlows.TryGetValue(key, out TcpFlowState? current) && current.ExpireTick == 0;
                    if (current != null) current.ExpireTick = expireAt;
                    else _tcpFlows[key] = new TcpFlowState(pid, expireAt);
                    _logger.LogTrace("  tcp flow marked closed, wasLive={WasLive} graceMs={GraceMs} count={Count} key={Key}", wasLive, TcpCloseGraceMs, _tcpFlows.Count, key);
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
                    if (_udpBinds.TryAdd(new UdpBindKey(local, lp), new UdpBindState(pid)))
                        UdpBindAdded?.Invoke(local, lp);
                }
                break;
        }
    }

    public void Dispose()
    {
        try { _cts.Cancel(); } catch { }

        PerPidHandle? all = _allHandle;
        _allHandle = null;
        if (all != null)
        {
            try { all.Handle.Shutdown(); } catch { }
            try { all.PumpTask.Wait(TimeSpan.FromSeconds(1)); } catch { }
            all.Handle.Dispose();
        }

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
        _pidDecisions.Clear();
        try { _cleanupTask?.Wait(TimeSpan.FromSeconds(1)); } catch { }
        _cts.Dispose();
    }
}
