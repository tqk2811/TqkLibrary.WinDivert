using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace TqkLibrary.WinDivert.Demo;

internal static class SuspendedProcessLauncher
{
    private const uint CREATE_SUSPENDED = 0x00000004;
    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;

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

    public sealed class SuspendedProcess : IDisposable
    {
        public uint Pid { get; }
        private IntPtr _processHandle;
        private IntPtr _threadHandle;
        private bool _resumed;

        internal SuspendedProcess(uint pid, IntPtr processHandle, IntPtr threadHandle)
        {
            Pid = pid;
            _processHandle = processHandle;
            _threadHandle = threadHandle;
        }

        public void Resume()
        {
            if (_resumed) return;
            uint prev = ResumeThread(_threadHandle);
            if (prev == unchecked((uint)-1))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "ResumeThread failed");
            _resumed = true;
        }

        public void Dispose()
        {
            // If we never resumed (e.g. redirector failed to start), kill the orphaned suspended child
            // so we don't leave it stuck in memory.
            if (!_resumed && _processHandle != IntPtr.Zero)
                TerminateProcess(_processHandle, 1);
            if (_threadHandle != IntPtr.Zero) { CloseHandle(_threadHandle); _threadHandle = IntPtr.Zero; }
            if (_processHandle != IntPtr.Zero) { CloseHandle(_processHandle); _processHandle = IntPtr.Zero; }
        }
    }

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
        return new SuspendedProcess(pi.dwProcessId, pi.hProcess, pi.hThread);
    }
}
