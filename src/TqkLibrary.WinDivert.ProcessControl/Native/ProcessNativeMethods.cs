using System;
using System.Runtime.InteropServices;

namespace TqkLibrary.WinDivert.ProcessControl.Native;

/// <summary>
/// The Win32 and NT entry points this assembly needs. P/Invoke declarations have to be static, so
/// they live here in one place rather than being duplicated across the classes that call them.
/// </summary>
internal static class ProcessNativeMethods
{
    internal const uint CREATE_SUSPENDED = 0x00000004;
    internal const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    internal const uint PROCESS_SUSPEND_RESUME = 0x0800;
    internal const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    internal const int ProcessBasicInformationClass = 0;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct STARTUPINFOW
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
    internal struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateProcessW")]
    internal static extern bool CreateProcess(
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
    internal static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    // Undocumented but stable across NT 4.0..Win11. Suspends/resumes every thread atomically —
    // simpler than enumerating threads via Toolhelp and racing with new thread creation.
    [DllImport("ntdll.dll")]
    internal static extern int NtSuspendProcess(IntPtr hProcess);

    [DllImport("ntdll.dll")]
    internal static extern int NtResumeProcess(IntPtr hProcess);

    [DllImport("ntdll.dll")]
    internal static extern int NtQueryInformationProcess(
        IntPtr handle, int infoClass, ref PROCESS_BASIC_INFORMATION pi, int piLen, out int retLen);
}
