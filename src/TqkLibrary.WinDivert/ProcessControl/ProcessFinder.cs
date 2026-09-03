using System;
using System.Collections.Generic;
using SysProcess = System.Diagnostics.Process;

namespace TqkLibrary.WinDivert.ProcessControl;

// Enumerates running processes for pickers and for rule matching.
//
// The SysProcess alias is deliberate: this namespace ends in "ProcessControl" rather than
// "Process" precisely to avoid shadowing System.Diagnostics.Process across the assembly, but the
// alias keeps the intent obvious at every call site.
public static class ProcessFinder
{
    // Every process the current user can see, sorted by name. Processes that vanish mid-enumeration
    // are skipped rather than throwing.
    public static IReadOnlyList<ProcessInfo> ListAll()
    {
        var list = new List<ProcessInfo>();
        foreach (var p in SysProcess.GetProcesses())
        {
            try
            {
                list.Add(new ProcessInfo((uint)p.Id, p.ProcessName, TryGetPath(p)));
            }
            catch { }
            finally { p.Dispose(); }
        }
        list.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
        return list;
    }

    // Exact process-name match (no ".exe", same semantics as Process.GetProcessesByName).
    public static IReadOnlyList<ProcessInfo> FindByName(string name)
    {
        var list = new List<ProcessInfo>();
        foreach (var p in SysProcess.GetProcessesByName(name))
        {
            try
            {
                list.Add(new ProcessInfo((uint)p.Id, p.ProcessName, TryGetPath(p)));
            }
            catch { }
            finally { p.Dispose(); }
        }
        return list;
    }

    public static ProcessInfo? FindById(uint pid)
    {
        try
        {
            using var p = SysProcess.GetProcessById((int)pid);
            return new ProcessInfo((uint)p.Id, p.ProcessName, TryGetPath(p));
        }
        catch
        {
            return null;
        }
    }

    private static string? TryGetPath(SysProcess p)
    {
        // Access denied for system processes and for a 32-bit host reading a 64-bit process.
        try { return p.MainModule?.FileName; } catch { return null; }
    }
}
