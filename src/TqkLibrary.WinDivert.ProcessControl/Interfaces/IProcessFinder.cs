using System.Collections.Generic;

namespace TqkLibrary.WinDivert.ProcessControl.Interfaces;

/// <summary>Enumerates running processes, for pickers and for matching routing rules by name.</summary>
public interface IProcessFinder
{
    /// <summary>
    /// Every process the current user can see, sorted by name. Processes that vanish
    /// mid-enumeration are skipped rather than throwing.
    /// </summary>
    IReadOnlyList<ProcessInfo> ListAll();

    /// <summary>Exact process-name match, without ".exe" — the same semantics as Process.GetProcessesByName.</summary>
    IReadOnlyList<ProcessInfo> FindByName(string name);

    /// <summary>Null when no such process is running (or it exited during the lookup).</summary>
    ProcessInfo? FindById(uint pid);
}
