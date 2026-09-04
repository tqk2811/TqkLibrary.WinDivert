namespace TqkLibrary.WinDivert.ProcessControl.Interfaces;

/// <summary>
/// Creates a monitor for one root process. A factory because the root pid is known only when a
/// session starts, not when the container is built.
/// </summary>
public interface IProcessTreeMonitorFactory
{
    /// <param name="pollIntervalMs">
    /// How often the process list is walked. There is no event for "a child appeared" that works
    /// without a driver, so this is a trade between latency and CPU.
    /// </param>
    IProcessTreeMonitor Create(uint rootPid, int pollIntervalMs = 500);
}
