namespace TqkLibrary.WinDivert.ProcessControl.Interfaces;

/// <summary>
/// Produces a process that is not running yet, so nothing it does can escape capture.
/// </summary>
public interface ISuspendedProcessLauncher
{
    /// <summary>
    /// Starts a new process suspended. Throws <see cref="System.ComponentModel.Win32Exception"/>
    /// when the executable cannot be started.
    /// </summary>
    ISuspendedProcess Launch(string exePath, string? args);

    /// <summary>
    /// Freezes a process that is already running. Needs PROCESS_SUSPEND_RESUME, so in practice
    /// Administrator. Be aware that a kernel-mode anti-cheat may read the freeze as tampering.
    /// </summary>
    ISuspendedProcess AttachSuspend(uint pid);
}
