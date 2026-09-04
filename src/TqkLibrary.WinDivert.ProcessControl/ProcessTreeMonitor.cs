using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TqkLibrary.WinDivert.ProcessControl.Native;
using SysProcess = System.Diagnostics.Process;

namespace TqkLibrary.WinDivert.ProcessControl;

// Polls the live process list and reports children/descendants of a root pid. Uses
// NtQueryInformationProcess(ProcessBasicInformation) to read InheritedFromUniqueProcessId for
// each running process — faster than WMI Win32_Process and works without admin for processes
// the user already owns. PID reuse is handled by spotting "new" pids that weren't in the prior
// snapshot, not by remembering the entire history.
//
// The SysProcess alias keeps the intent readable; the namespace is "ProcessControl" rather than
// "Process" so it can never shadow System.Diagnostics.Process elsewhere in the assembly.
public sealed class ProcessTreeMonitor : IProcessTreeMonitor
{
    private readonly uint _rootPid;
    private readonly int _pollIntervalMs;
    private readonly ILogger<ProcessTreeMonitor> _logger;
    private readonly CancellationTokenSource _cts = new();
    private readonly HashSet<uint> _knownDescendants = new();
    private Task? _pollTask;

    public event Action<uint, uint>? ChildSpawned; // (childPid, parentPid)

    public ProcessTreeMonitor(uint rootPid, ILogger<ProcessTreeMonitor> logger, int pollIntervalMs = 500)
    {
        _rootPid = rootPid;
        _pollIntervalMs = pollIntervalMs;
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _knownDescendants.Add(rootPid);
    }

    public void Start()
    {
        if (_pollTask != null) throw new InvalidOperationException("Already started");
        _pollTask = Task.Run(() => PollLoop(_cts.Token));
    }

    private async Task PollLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { Scan(); }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Scan of the process tree failed");
            }
            try { await Task.Delay(_pollIntervalMs, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
        }
    }

    private void Scan()
    {
        SysProcess[] processes = SysProcess.GetProcesses();
        try
        {
            var parentOf = new Dictionary<uint, uint>(processes.Length);
            foreach (var p in processes)
            {
                try
                {
                    uint pid = (uint)p.Id;
                    uint? parent = TryReadParentPid(pid);
                    if (parent.HasValue) parentOf[pid] = parent.Value;
                }
                catch { /* process gone between GetProcesses and OpenProcess — ignore */ }
            }

            // BFS from root to find every descendant currently alive.
            var seen = new HashSet<uint> { _rootPid };
            var stack = new Stack<uint>();
            stack.Push(_rootPid);
            while (stack.Count > 0)
            {
                uint cur = stack.Pop();
                foreach (var kv in parentOf)
                {
                    if (kv.Value == cur && seen.Add(kv.Key))
                        stack.Push(kv.Key);
                }
            }

            // Fire ChildSpawned for any descendant we haven't seen before. Don't bother removing
            // dead pids — SocketTracker handles those via SocketClose events + cleanup.
            foreach (uint pid in seen)
            {
                if (pid == _rootPid) continue;
                if (_knownDescendants.Add(pid))
                    ChildSpawned?.Invoke(pid, parentOf.TryGetValue(pid, out uint parent) ? parent : 0);
            }
        }
        finally
        {
            foreach (var p in processes) { try { p.Dispose(); } catch { } }
        }
    }

    private static uint? TryReadParentPid(uint pid)
    {
        // PID 0 (System Idle) and 4 (System) can't be opened — skip.
        if (pid <= 4) return null;
        IntPtr h = ProcessNativeMethods.OpenProcess(ProcessNativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            var pbi = new ProcessNativeMethods.PROCESS_BASIC_INFORMATION();
            int status = ProcessNativeMethods.NtQueryInformationProcess(
                h, ProcessNativeMethods.ProcessBasicInformationClass, ref pbi, Marshal.SizeOf(pbi), out _);
            if (status < 0) return null;
            return (uint)pbi.InheritedFromUniqueProcessId.ToInt64();
        }
        finally
        {
            ProcessNativeMethods.CloseHandle(h);
        }
    }

    public void Dispose()
    {
        try { _cts.Cancel(); } catch { }
        try { _pollTask?.Wait(TimeSpan.FromSeconds(1)); } catch { }
        _cts.Dispose();
    }
}
