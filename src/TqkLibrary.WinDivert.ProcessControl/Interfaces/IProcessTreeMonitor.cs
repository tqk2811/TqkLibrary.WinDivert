using System;

namespace TqkLibrary.WinDivert.ProcessControl.Interfaces;

/// <summary>
/// Watches a process for descendants, so a launcher that spawns its real work into a child (as
/// game launchers and browsers do) does not slip out of the redirect scope.
/// </summary>
public interface IProcessTreeMonitor : IDisposable
{
    /// <summary>Raised once per newly seen descendant, as (childPid, parentPid).</summary>
    event Action<uint, uint>? ChildSpawned;

    void Start();
}
