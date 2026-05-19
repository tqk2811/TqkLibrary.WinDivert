using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;

namespace TqkLibrary.WinDivert.Native;

// Snapshot helpers for the kernel TCP/UDP connection tables. Used by SocketTracker to recover
// sockets that already existed before the SOCKET-layer filter attached — those sockets never
// fire SocketConnect/SocketBind events, so without this snapshot every packet from them falls
// through `IsTracked*` and leaks past the redirect.
internal static class IpHlpApi
{
    private const string Dll = "iphlpapi.dll";
    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const uint MIB_TCP_STATE_LISTEN = 2;

    private enum TCP_TABLE_CLASS
    {
        TCP_TABLE_OWNER_PID_ALL = 5,
    }

    private enum UDP_TABLE_CLASS
    {
        UDP_TABLE_OWNER_PID = 1,
    }

    [DllImport(Dll, SetLastError = true)]
    private static extern int GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        TCP_TABLE_CLASS tableClass,
        int reserved);

    [DllImport(Dll, SetLastError = true)]
    private static extern int GetExtendedUdpTable(
        IntPtr pUdpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        UDP_TABLE_CLASS tableClass,
        int reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddr;
        public uint LocalScopeId;
        public uint LocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] RemoteAddr;
        public uint RemoteScopeId;
        public uint RemotePort;
        public uint State;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDPROW_OWNER_PID
    {
        public uint LocalAddr;
        public uint LocalPort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddr;
        public uint LocalScopeId;
        public uint LocalPort;
        public uint OwningPid;
    }

    public readonly struct TcpFlow
    {
        public TcpFlow(IPAddress local, ushort localPort, IPAddress remote, ushort remotePort)
        {
            LocalAddr = local;
            LocalPort = localPort;
            RemoteAddr = remote;
            RemotePort = remotePort;
        }
        public IPAddress LocalAddr { get; }
        public ushort LocalPort { get; }
        public IPAddress RemoteAddr { get; }
        public ushort RemotePort { get; }
    }

    public readonly struct UdpBind
    {
        public UdpBind(IPAddress local, ushort localPort)
        {
            LocalAddr = local;
            LocalPort = localPort;
        }
        public IPAddress LocalAddr { get; }
        public ushort LocalPort { get; }
    }

    // Port DWORDs from MIB_*_OWNER_PID encode the port in network byte order in the low 2 bytes.
    private static ushort PortFromDword(uint raw)
    {
        ushort lo = (ushort)(raw & 0xFFFF);
        return (ushort)((lo << 8) | (lo >> 8));
    }

    public static IEnumerable<TcpFlow> EnumerateProcessTcpFlows(uint pid)
    {
        foreach (var f in EnumerateTcp4(pid)) yield return f;
        foreach (var f in EnumerateTcp6(pid)) yield return f;
    }

    public static IEnumerable<UdpBind> EnumerateProcessUdpBinds(uint pid)
    {
        foreach (var b in EnumerateUdp4(pid)) yield return b;
        foreach (var b in EnumerateUdp6(pid)) yield return b;
    }

    private static IEnumerable<TcpFlow> EnumerateTcp4(uint pid)
    {
        IntPtr buf = IntPtr.Zero;
        int size = 0;
        try
        {
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET,
                TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
            if (size <= 0) yield break;
            buf = Marshal.AllocHGlobal(size);
            int ret = GetExtendedTcpTable(buf, ref size, false, AF_INET,
                TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret != 0) yield break;

            int count = Marshal.ReadInt32(buf);
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
            for (int i = 0; i < count; i++)
            {
                IntPtr rowPtr = IntPtr.Add(buf, 4 + i * rowSize);
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                if (row.OwningPid != pid) continue;
                if (row.State == MIB_TCP_STATE_LISTEN) continue;
                yield return new TcpFlow(
                    new IPAddress(BitConverter.GetBytes(row.LocalAddr)),
                    PortFromDword(row.LocalPort),
                    new IPAddress(BitConverter.GetBytes(row.RemoteAddr)),
                    PortFromDword(row.RemotePort));
            }
        }
        finally
        {
            if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
        }
    }

    private static IEnumerable<TcpFlow> EnumerateTcp6(uint pid)
    {
        IntPtr buf = IntPtr.Zero;
        int size = 0;
        try
        {
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET6,
                TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
            if (size <= 0) yield break;
            buf = Marshal.AllocHGlobal(size);
            int ret = GetExtendedTcpTable(buf, ref size, false, AF_INET6,
                TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret != 0) yield break;

            int count = Marshal.ReadInt32(buf);
            int rowSize = Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();
            for (int i = 0; i < count; i++)
            {
                IntPtr rowPtr = IntPtr.Add(buf, 4 + i * rowSize);
                var row = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(rowPtr);
                if (row.OwningPid != pid) continue;
                if (row.State == MIB_TCP_STATE_LISTEN) continue;
                yield return new TcpFlow(
                    new IPAddress(row.LocalAddr),
                    PortFromDword(row.LocalPort),
                    new IPAddress(row.RemoteAddr),
                    PortFromDword(row.RemotePort));
            }
        }
        finally
        {
            if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
        }
    }

    private static IEnumerable<UdpBind> EnumerateUdp4(uint pid)
    {
        IntPtr buf = IntPtr.Zero;
        int size = 0;
        try
        {
            GetExtendedUdpTable(IntPtr.Zero, ref size, false, AF_INET,
                UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
            if (size <= 0) yield break;
            buf = Marshal.AllocHGlobal(size);
            int ret = GetExtendedUdpTable(buf, ref size, false, AF_INET,
                UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
            if (ret != 0) yield break;

            int count = Marshal.ReadInt32(buf);
            int rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();
            for (int i = 0; i < count; i++)
            {
                IntPtr rowPtr = IntPtr.Add(buf, 4 + i * rowSize);
                var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);
                if (row.OwningPid != pid) continue;
                yield return new UdpBind(
                    new IPAddress(BitConverter.GetBytes(row.LocalAddr)),
                    PortFromDword(row.LocalPort));
            }
        }
        finally
        {
            if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
        }
    }

    private static IEnumerable<UdpBind> EnumerateUdp6(uint pid)
    {
        IntPtr buf = IntPtr.Zero;
        int size = 0;
        try
        {
            GetExtendedUdpTable(IntPtr.Zero, ref size, false, AF_INET6,
                UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
            if (size <= 0) yield break;
            buf = Marshal.AllocHGlobal(size);
            int ret = GetExtendedUdpTable(buf, ref size, false, AF_INET6,
                UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
            if (ret != 0) yield break;

            int count = Marshal.ReadInt32(buf);
            int rowSize = Marshal.SizeOf<MIB_UDP6ROW_OWNER_PID>();
            for (int i = 0; i < count; i++)
            {
                IntPtr rowPtr = IntPtr.Add(buf, 4 + i * rowSize);
                var row = Marshal.PtrToStructure<MIB_UDP6ROW_OWNER_PID>(rowPtr);
                if (row.OwningPid != pid) continue;
                yield return new UdpBind(
                    new IPAddress(row.LocalAddr),
                    PortFromDword(row.LocalPort));
            }
        }
        finally
        {
            if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
        }
    }
}
