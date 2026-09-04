using System;

namespace TqkLibrary.WinDivert.ProcessControl.Interfaces;

/// <summary>
/// A frozen process, held still so a tracker can install its filters before the process gets a
/// chance to open a socket.
/// </summary>
/// <remarks>
/// Dispose without <see cref="Resume"/> is deliberately asymmetric, because the right answer
/// depends on who created the process: one this library launched is terminated (an orphan left
/// suspended forever is worse than no process), while one it merely attached to is resumed — the
/// user's application existed before us and killing it is not ours to decide.
/// </remarks>
public interface ISuspendedProcess : IDisposable
{
    uint Pid { get; }

    /// <summary>Lets the process run. Idempotent.</summary>
    void Resume();
}
