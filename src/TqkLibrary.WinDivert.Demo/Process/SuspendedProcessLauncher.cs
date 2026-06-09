using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace TqkLibrary.WinDivert.Demo.Process;

internal static partial class SuspendedProcessLauncher
{
    private const uint CREATE_SUSPENDED = 0x00000004;
    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const uint PROCESS_SUSPEND_RESUME = 0x0800;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFOW
    {
        public uint cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public uint dwX, dwY, dwXSize, dwYSize;
        public uint dwXCountChars, dwYCountChars, dwFillAttribute;
        public uint dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateProcessW")]
    private static extern bool CreateProcess(
        string? lpApplicationName,
        System.Text.StringBuilder lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        ref STARTUPINFOW lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    // Undocumented but stable across NT 4.0..Win11. Suspends/resumes every thread atomically —
    // simpler than enumerating threads via Toolhelp and racing with new thread creation.
    [DllImport("ntdll.dll")]
    private static extern int NtSuspendProcess(IntPtr hProcess);

    [DllImport("ntdll.dll")]
    private static extern int NtResumeProcess(IntPtr hProcess);

    public static SuspendedProcess Launch(string exePath, string? args)
    {
        // CreateProcess requires lpCommandLine be writable; use StringBuilder.
        // First token must be the exe (quoted to be safe).
        var cmd = new System.Text.StringBuilder();
        cmd.Append('"').Append(exePath).Append('"');
        if (!string.IsNullOrEmpty(args))
            cmd.Append(' ').Append(args);

        var si = new STARTUPINFOW { cb = (uint)Marshal.SizeOf(typeof(STARTUPINFOW)) };
        if (!CreateProcess(
                null,
                cmd,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                IntPtr.Zero,
                null,
                ref si,
                out var pi))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"CreateProcess failed for: {cmd}");
        }
        return new SuspendedProcess(pi.dwProcessId, pi.hProcess, pi.hThread, isAttachMode: false);
    }

    // Freezes a running process so the tracker can install its filter before any new socket is
    // created. Caller MUST Resume() once the tracker is ready (or Dispose, which auto-resumes
    // in attach mode). Be aware: a kernel-mode anti-cheat may detect the freeze as tampering.
    public static SuspendedProcess AttachSuspend(uint pid)
    {
        IntPtr handle = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (handle == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"OpenProcess(pid={pid}) failed (need PROCESS_SUSPEND_RESUME — run as Admin)");

        int status = NtSuspendProcess(handle);
        if (status < 0)
        {
            CloseHandle(handle);
            throw new Win32Exception(status, $"NtSuspendProcess(pid={pid}) failed (NTSTATUS=0x{status:X8})");
        }
        return new SuspendedProcess(pid, handle, IntPtr.Zero, isAttachMode: true);
    }
}
