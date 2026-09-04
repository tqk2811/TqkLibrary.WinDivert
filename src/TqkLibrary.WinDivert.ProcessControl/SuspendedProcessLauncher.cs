using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using TqkLibrary.WinDivert.ProcessControl.Native;

namespace TqkLibrary.WinDivert.ProcessControl;

/// <summary>
/// Starts a process frozen, or freezes one that is already running, so a redirector can attach
/// before the process opens its first socket.
/// </summary>
/// <remarks>
/// This is what makes "escaped flow" handling mostly theoretical: a process that has never run
/// cannot have a connection in flight, so every one of its flows is captured from its SYN.
/// Stateless — one instance serves the whole process.
/// </remarks>
public sealed class SuspendedProcessLauncher : ISuspendedProcessLauncher
{
    public ISuspendedProcess Launch(string exePath, string? args)
    {
        if (exePath is null) throw new ArgumentNullException(nameof(exePath));

        // CreateProcess requires lpCommandLine be writable; use StringBuilder.
        // First token must be the exe (quoted to be safe).
        var cmd = new System.Text.StringBuilder();
        cmd.Append('"').Append(exePath).Append('"');
        if (!string.IsNullOrEmpty(args))
            cmd.Append(' ').Append(args);

        var si = new ProcessNativeMethods.STARTUPINFOW
        {
            cb = (uint)Marshal.SizeOf(typeof(ProcessNativeMethods.STARTUPINFOW)),
        };
        if (!ProcessNativeMethods.CreateProcess(
                null,
                cmd,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                ProcessNativeMethods.CREATE_SUSPENDED | ProcessNativeMethods.CREATE_UNICODE_ENVIRONMENT,
                IntPtr.Zero,
                null,
                ref si,
                out ProcessNativeMethods.PROCESS_INFORMATION pi))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"CreateProcess failed for: {cmd}");
        }
        return new SuspendedProcess(pi.dwProcessId, pi.hProcess, pi.hThread, isAttachMode: false);
    }

    public ISuspendedProcess AttachSuspend(uint pid)
    {
        IntPtr handle = ProcessNativeMethods.OpenProcess(
            ProcessNativeMethods.PROCESS_SUSPEND_RESUME | ProcessNativeMethods.PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            pid);
        if (handle == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"OpenProcess(pid={pid}) failed (need PROCESS_SUSPEND_RESUME — run as Admin)");

        int status = ProcessNativeMethods.NtSuspendProcess(handle);
        if (status < 0)
        {
            ProcessNativeMethods.CloseHandle(handle);
            throw new Win32Exception(status, $"NtSuspendProcess(pid={pid}) failed (NTSTATUS=0x{status:X8})");
        }
        return new SuspendedProcess(pid, handle, IntPtr.Zero, isAttachMode: true);
    }
}
