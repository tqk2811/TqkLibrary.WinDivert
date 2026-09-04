using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using TqkLibrary.WinDivert.ProcessControl.Native;

namespace TqkLibrary.WinDivert.ProcessControl;

/// <summary>
/// Holds a process frozen, and knows how it got that way — which is what decides what happens if
/// it is disposed without ever being resumed. See <see cref="ISuspendedProcess"/>.
/// </summary>
public sealed class SuspendedProcess : ISuspendedProcess
{
    public uint Pid { get; }

    private IntPtr _processHandle;
    private IntPtr _threadHandle;       // 0 for attach mode (no main-thread handle)
    private readonly bool _isAttachMode;
    private bool _resumed;

    internal SuspendedProcess(uint pid, IntPtr processHandle, IntPtr threadHandle, bool isAttachMode)
    {
        Pid = pid;
        _processHandle = processHandle;
        _threadHandle = threadHandle;
        _isAttachMode = isAttachMode;
    }

    public void Resume()
    {
        if (_resumed) return;
        if (_isAttachMode)
        {
            int status = ProcessNativeMethods.NtResumeProcess(_processHandle);
            if (status < 0)
                throw new Win32Exception(status, $"NtResumeProcess failed (NTSTATUS=0x{status:X8})");
        }
        else
        {
            uint prev = ProcessNativeMethods.ResumeThread(_threadHandle);
            if (prev == unchecked((uint)-1))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "ResumeThread failed");
        }
        _resumed = true;
    }

    public void Dispose()
    {
        // If we never resumed:
        //   Launch mode  — we created the process, kill the orphan so it doesn't sit suspended.
        //   Attach mode  — the process pre-existed; we MUST resume it back to its original state.
        //                  Terminating would kill the user's app, which is not our right to do.
        if (!_resumed && _processHandle != IntPtr.Zero)
        {
            if (_isAttachMode) ProcessNativeMethods.NtResumeProcess(_processHandle);
            else ProcessNativeMethods.TerminateProcess(_processHandle, 1);
        }
        if (_threadHandle != IntPtr.Zero) { ProcessNativeMethods.CloseHandle(_threadHandle); _threadHandle = IntPtr.Zero; }
        if (_processHandle != IntPtr.Zero) { ProcessNativeMethods.CloseHandle(_processHandle); _processHandle = IntPtr.Zero; }
    }
}
