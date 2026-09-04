namespace TqkLibrary.WinDivert.Flow.Interfaces;

/// <summary>
/// Creates a tracker scoped to a process. A factory rather than a registered instance because the
/// root pid and the handle priority are decided when a redirect session starts, not when the
/// container is built.
/// </summary>
public interface ISocketTrackerFactory
{
    /// <param name="processId">
    /// Root process to follow. Zero starts with an empty scope, for a caller that feeds pids in
    /// through <see cref="ISocketTracker.AddProcess"/> as a watcher discovers them.
    /// </param>
    /// <param name="socketPriority">
    /// Priority of the SOCKET-layer handles, deciding this tracker's order relative to other
    /// WinDivert clients on the machine.
    /// </param>
    ISocketTracker Create(uint processId, short socketPriority = 0);
}
