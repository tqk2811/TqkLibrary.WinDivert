using System.Collections.Generic;
using SysProcess = System.Diagnostics.Process;

namespace TqkLibrary.WinDivert.Process;

public static class ProcessFinder
{
    public static IReadOnlyList<ProcessInfo> ListAll()
    {
        var list = new List<ProcessInfo>();
        foreach (var p in SysProcess.GetProcesses())
        {
            try
            {
                string? path = null;
                try { path = p.MainModule?.FileName; } catch { /* access denied for system processes */ }
                list.Add(new ProcessInfo((uint)p.Id, p.ProcessName, path));
            }
            catch { }
            finally { p.Dispose(); }
        }
        list.Sort((a, b) => string.Compare(a.Name, b.Name, System.StringComparison.OrdinalIgnoreCase));
        return list;
    }

    public static IReadOnlyList<ProcessInfo> FindByName(string name)
    {
        var list = new List<ProcessInfo>();
        foreach (var p in SysProcess.GetProcessesByName(name))
        {
            try
            {
                string? path = null;
                try { path = p.MainModule?.FileName; } catch { }
                list.Add(new ProcessInfo((uint)p.Id, p.ProcessName, path));
            }
            finally { p.Dispose(); }
        }
        return list;
    }
}
