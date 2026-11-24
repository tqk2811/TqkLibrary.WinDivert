using TqkLibrary.WinDivert.ProcessControl;
using Xunit;

namespace TqkLibrary.WinDivert.Tests;

/// <summary>No real process: zero handles are enough to reach the paths under test.</summary>
public class SuspendedProcessTests
{
    // Resume() after Dispose() used to call into the closed handle and throw a Win32Exception
    // that said nothing about the real mistake (backlog B14).
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ResumeAfterDisposeDoesNothing(bool isAttachMode)
    {
        var process = new SuspendedProcess(1234, IntPtr.Zero, IntPtr.Zero, isAttachMode);
        process.Dispose();

        process.Resume();
    }
}
