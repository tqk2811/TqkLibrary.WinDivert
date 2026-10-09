using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Extensions.Logging;

namespace TqkLibrary.WinDivert.Pipeline.Helpers;

/// <summary>
/// Gives each latency-critical pump thread a core of its own as its IDEAL processor, and keeps
/// Windows from treating it as background work to be slowed down.
/// </summary>
/// <remarks>
/// An ideal processor is a hint, not an affinity: the scheduler starts the thread there when that
/// core is free and moves it anywhere else when it is not, so a pump never waits for one busy core
/// while others idle — the reason hard affinity is not used.
/// <para>
/// Cores are ranked from <c>GetSystemCpuSetInformation</c>:
/// </para>
/// <list type="bullet">
/// <item>highest <c>EfficiencyClass</c> first — on an Intel hybrid part that is the P-cores, on a
/// part without hybrid cores (most AMD) every core shares one class and this changes nothing;</item>
/// <item>one logical processor per physical core, the core's first (primary) hardware thread, so
/// two pumps never share a core through SMT/Hyper-Threading. With SMT off (or on a part without
/// it) every core has a single logical processor and the grouping is a no-op;</item>
/// <item>core 0 last: it takes most of the machine's interrupts and DPCs.</item>
/// </list>
/// Pumps are dealt those cores round-robin, so six pumps land on six different physical cores
/// when there are that many.
/// </remarks>
internal static class PumpCoreHints
{
    private static readonly Lazy<ProcessorNumber[]> RankedCores = new(LoadRankedCores);
    private static int _next = -1;
    private static int _logicalCount;
    private static int _efficiencyClasses;

    /// <summary>Applies both hints to the calling thread; failures are logged and ignored.</summary>
    public static void ApplyToCurrentThread(ILogger? logger)
    {
        DisablePowerThrottling(logger);

        ProcessorNumber[] cores;
        try
        {
            cores = RankedCores.Value;
        }
        catch (Exception ex)
        {
            logger?.LogDebug(ex, "could not read the CPU set information; the pump thread keeps no ideal processor");
            return;
        }
        if (cores.Length == 0) return;

        int slot = Interlocked.Increment(ref _next);
        if (slot == 0)
            logger?.LogDebug(
                "CPU topology: {Cores} physical cores, {Logical} logical processors, SMT/Hyper-Threading {Smt}, {Classes} efficiency class(es) (hybrid={Hybrid})",
                cores.Length, _logicalCount, _logicalCount > cores.Length ? "on" : "off", _efficiencyClasses, _efficiencyClasses > 1);
        ProcessorNumber core = cores[(int)((uint)slot % (uint)cores.Length)];
        if (SetThreadIdealProcessorEx(GetCurrentThread(), ref core, out _))
            logger?.LogDebug("pump thread ideal processor group={Group} cpu={Cpu}", core.Group, core.Number);
        else
            logger?.LogDebug("could not set the pump thread's ideal processor, win32={Win32}", Marshal.GetLastWin32Error());
    }

    // Windows 11 may run a thread it judges to be background work (EcoQoS) at reduced clocks or on
    // efficiency cores. A pump spends its life blocked in the driver, which is exactly what such
    // work looks like, yet every packet of the machine waits on it.
    private static void DisablePowerThrottling(ILogger? logger)
    {
        ThreadPowerThrottlingState state = new()
        {
            Version = ThreadPowerThrottlingCurrentVersion,
            ControlMask = ThreadPowerThrottlingExecutionSpeed,
            StateMask = 0,
        };
        try
        {
            if (!SetThreadInformation(GetCurrentThread(), ThreadPowerThrottling, ref state, Marshal.SizeOf<ThreadPowerThrottlingState>()))
                logger?.LogDebug("could not opt the pump thread out of power throttling, win32={Win32}", Marshal.GetLastWin32Error());
        }
        catch (EntryPointNotFoundException)
        {
            // Older than Windows 10 1709: no power throttling to opt out of.
        }
    }

    private static ProcessorNumber[] LoadRankedCores()
    {
        GetSystemCpuSetInformation(IntPtr.Zero, 0, out int length, IntPtr.Zero, 0);
        if (length <= 0) return Array.Empty<ProcessorNumber>();

        IntPtr buffer = Marshal.AllocHGlobal(length);
        try
        {
            if (!GetSystemCpuSetInformation(buffer, length, out length, IntPtr.Zero, 0))
                return Array.Empty<ProcessorNumber>();

            List<CpuSetEntry> sets = new();
            for (int offset = 0; offset + CpuSetMinSize <= length;)
            {
                IntPtr entry = buffer + offset;
                int size = Marshal.ReadInt32(entry, 0);
                if (size <= 0) break;
                if (Marshal.ReadInt32(entry, 4) == CpuSetInformation && size >= CpuSetMinSize)
                {
                    sets.Add(new CpuSetEntry(
                        Group: (ushort)Marshal.ReadInt16(entry, 12),
                        LogicalIndex: Marshal.ReadByte(entry, 14),
                        CoreIndex: Marshal.ReadByte(entry, 15),
                        EfficiencyClass: Marshal.ReadByte(entry, 18)));
                }
                offset += size;
            }
            _logicalCount = sets.Count;
            _efficiencyClasses = sets.Select(s => s.EfficiencyClass).Distinct().Count();
            return RankCores(sets);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>Orders physical cores best first and returns each one's primary logical processor.</summary>
    internal static ProcessorNumber[] RankCores(IEnumerable<CpuSetEntry> sets)
        => sets
            // SMT siblings share (Group, CoreIndex); the lowest logical index is the primary thread.
            .GroupBy(s => (s.Group, s.CoreIndex))
            .Select(g => g.OrderBy(s => s.LogicalIndex).First())
            .OrderByDescending(s => s.EfficiencyClass)
            .ThenBy(s => s.Group == 0 && s.CoreIndex == 0)
            .ThenBy(s => s.Group)
            .ThenBy(s => s.CoreIndex)
            .Select(s => new ProcessorNumber { Group = s.Group, Number = s.LogicalIndex })
            .ToArray();

    internal readonly record struct CpuSetEntry(ushort Group, byte LogicalIndex, byte CoreIndex, byte EfficiencyClass);

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProcessorNumber
    {
        public ushort Group;
        public byte Number;
        public byte Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ThreadPowerThrottlingState
    {
        public uint Version;
        public uint ControlMask;
        public uint StateMask;
    }

    // SYSTEM_CPU_SET_INFORMATION: Size(0) Type(4) Id(8) Group(12) LogicalProcessorIndex(14)
    // CoreIndex(15) LastLevelCacheIndex(16) NumaNodeIndex(17) EfficiencyClass(18) AllFlags(19) ...
    private const int CpuSetMinSize = 20;
    private const int CpuSetInformation = 0;
    private const int ThreadPowerThrottling = 3;
    private const uint ThreadPowerThrottlingCurrentVersion = 1;
    private const uint ThreadPowerThrottlingExecutionSpeed = 1;

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentThread();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSystemCpuSetInformation(IntPtr information, int bufferLength, out int returnedLength, IntPtr process, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetThreadIdealProcessorEx(IntPtr thread, ref ProcessorNumber idealProcessor, out ProcessorNumber previousIdealProcessor);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetThreadInformation(IntPtr thread, int informationClass, ref ThreadPowerThrottlingState information, int informationSize);
}
