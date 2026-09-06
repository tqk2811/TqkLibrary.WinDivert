using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;

namespace TqkLibrary.WinDivert.Native;

// Snapshot helpers for the kernel TCP/UDP connection tables. Used by SocketTracker to recover
// sockets that already existed before the SOCKET-layer filter attached — those sockets never
// fire SocketConnect/SocketBind events, so without this snapshot every packet from them falls
// through `IsTracked*` and leaks past the redirect.
//
// The API is deliberately shaped around a PREDICATE over pids rather than a single pid. The
// kernel tables are machine-wide: asking about one process still reads every row of every table,
// so a caller tracking N processes used to pay N full reads of the same four tables. Chrome alone
// runs dozens of processes, and this ran on the packet pump thread for every SYN — the single
// largest source of connection-setup latency this redirector had. One sweep now answers for the
// whole tracked set.
internal static class IpHlpApi
{
    private const string Dll = "iphlpapi.dll";
    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const uint MIB_TCP_STATE_LISTEN = 2;
    private const int ERROR_INSUFFICIENT_BUFFER = 122;

    // Sizes of the MIB_*_OWNER_PID rows. Every member is a DWORD or a fixed 16-byte array, so the
    // structures are packed at 4-byte alignment on every architecture and these are exact.
    private const int TcpRow4Size = 24;   // State, LocalAddr, LocalPort, RemoteAddr, RemotePort, Pid
    private const int TcpRow6Size = 56;   // LocalAddr[16], LocalScope, LocalPort, RemoteAddr[16], RemoteScope, RemotePort, State, Pid
    private const int UdpRow4Size = 12;   // LocalAddr, LocalPort, Pid
    private const int UdpRow6Size = 28;   // LocalAddr[16], LocalScope, LocalPort, Pid

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

    /// <summary>
    /// Reads the kernel TCP tables (IPv4 and IPv6) once and reports every non-listening row whose
    /// owner <paramref name="wanted"/> accepts. The predicate is tested before any object is built,
    /// so rows belonging to untracked processes cost only a few span reads.
    /// </summary>
    public static void SnapshotTcpFlows(Func<uint, bool> wanted, Action<uint, TcpFlow> visit)
    {
        SnapshotTcp4(wanted, visit);
        SnapshotTcp6(wanted, visit);
    }

    /// <summary>Same, for the UDP bind tables.</summary>
    public static void SnapshotUdpBinds(Func<uint, bool> wanted, Action<uint, UdpBind> visit)
    {
        SnapshotUdp4(wanted, visit);
        SnapshotUdp6(wanted, visit);
    }

    public static IEnumerable<TcpFlow> EnumerateProcessTcpFlows(uint pid)
    {
        var found = new List<TcpFlow>();
        SnapshotTcpFlows(p => p == pid, (_, f) => found.Add(f));
        return found;
    }

    public static IEnumerable<UdpBind> EnumerateProcessUdpBinds(uint pid)
    {
        var found = new List<UdpBind>();
        SnapshotUdpBinds(p => p == pid, (_, b) => found.Add(b));
        return found;
    }

    // Copies one kernel table into managed memory. Returns null when the table cannot be read.
    //
    // The size is queried and then re-queried on ERROR_INSUFFICIENT_BUFFER: the table can grow
    // between the sizing call and the read on a machine that is opening connections, and treating
    // that as "no table" would silently lose every tracked flow for that sweep.
    private static byte[]? ReadTable(bool tcp, int af, out int length)
    {
        length = 0;
        int size = 0;
        for (int attempt = 0; attempt < 4; attempt++)
        {
            if (size <= 0)
            {
                int probe = tcp
                    ? GetExtendedTcpTable(IntPtr.Zero, ref size, false, af, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0)
                    : GetExtendedUdpTable(IntPtr.Zero, ref size, false, af, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
                if (probe != ERROR_INSUFFICIENT_BUFFER && probe != 0) return null;
                if (size <= 0) return null;
            }

            // Ask for a little more than the driver reported, so the common "one more connection
            // appeared" case is absorbed without a second round trip.
            size += size / 8 + 256;
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                int ret = tcp
                    ? GetExtendedTcpTable(buf, ref size, false, af, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0)
                    : GetExtendedUdpTable(buf, ref size, false, af, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
                if (ret == ERROR_INSUFFICIENT_BUFFER) continue;  // size now holds what it really needs
                if (ret != 0) return null;

                byte[] managed = new byte[size];
                Marshal.Copy(buf, managed, 0, size);
                length = size;
                return managed;
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }
        return null;
    }

    // Row count plus the offset the rows start at, or false when the buffer is too short to hold
    // even the header.
    private static bool TryReadHeader(ReadOnlySpan<byte> table, out int count)
    {
        if (table.Length < 4) { count = 0; return false; }
        count = BinaryPrimitives.ReadInt32LittleEndian(table);
        return count >= 0;
    }

    private static void SnapshotTcp4(Func<uint, bool> wanted, Action<uint, TcpFlow> visit)
    {
        byte[]? table = ReadTable(tcp: true, AF_INET, out int length);
        if (table == null) return;
        ReadOnlySpan<byte> span = table.AsSpan(0, length);
        if (!TryReadHeader(span, out int count)) return;

        for (int i = 0; i < count; i++)
        {
            int offset = 4 + i * TcpRow4Size;
            if (offset + TcpRow4Size > length) return;
            ReadOnlySpan<byte> row = span.Slice(offset, TcpRow4Size);

            uint pid = BinaryPrimitives.ReadUInt32LittleEndian(row.Slice(20, 4));
            if (!wanted(pid)) continue;
            if (BinaryPrimitives.ReadUInt32LittleEndian(row.Slice(0, 4)) == MIB_TCP_STATE_LISTEN) continue;

            visit(pid, new TcpFlow(
                new IPAddress(row.Slice(4, 4)),
                PortFromDword(BinaryPrimitives.ReadUInt32LittleEndian(row.Slice(8, 4))),
                new IPAddress(row.Slice(12, 4)),
                PortFromDword(BinaryPrimitives.ReadUInt32LittleEndian(row.Slice(16, 4)))));
        }
    }

    private static void SnapshotTcp6(Func<uint, bool> wanted, Action<uint, TcpFlow> visit)
    {
        byte[]? table = ReadTable(tcp: true, AF_INET6, out int length);
        if (table == null) return;
        ReadOnlySpan<byte> span = table.AsSpan(0, length);
        if (!TryReadHeader(span, out int count)) return;

        for (int i = 0; i < count; i++)
        {
            int offset = 4 + i * TcpRow6Size;
            if (offset + TcpRow6Size > length) return;
            ReadOnlySpan<byte> row = span.Slice(offset, TcpRow6Size);

            uint pid = BinaryPrimitives.ReadUInt32LittleEndian(row.Slice(52, 4));
            if (!wanted(pid)) continue;
            if (BinaryPrimitives.ReadUInt32LittleEndian(row.Slice(48, 4)) == MIB_TCP_STATE_LISTEN) continue;

            visit(pid, new TcpFlow(
                new IPAddress(row.Slice(0, 16)),
                PortFromDword(BinaryPrimitives.ReadUInt32LittleEndian(row.Slice(20, 4))),
                new IPAddress(row.Slice(24, 16)),
                PortFromDword(BinaryPrimitives.ReadUInt32LittleEndian(row.Slice(44, 4)))));
        }
    }

    private static void SnapshotUdp4(Func<uint, bool> wanted, Action<uint, UdpBind> visit)
    {
        byte[]? table = ReadTable(tcp: false, AF_INET, out int length);
        if (table == null) return;
        ReadOnlySpan<byte> span = table.AsSpan(0, length);
        if (!TryReadHeader(span, out int count)) return;

        for (int i = 0; i < count; i++)
        {
            int offset = 4 + i * UdpRow4Size;
            if (offset + UdpRow4Size > length) return;
            ReadOnlySpan<byte> row = span.Slice(offset, UdpRow4Size);

            uint pid = BinaryPrimitives.ReadUInt32LittleEndian(row.Slice(8, 4));
            if (!wanted(pid)) continue;

            visit(pid, new UdpBind(
                new IPAddress(row.Slice(0, 4)),
                PortFromDword(BinaryPrimitives.ReadUInt32LittleEndian(row.Slice(4, 4)))));
        }
    }

    private static void SnapshotUdp6(Func<uint, bool> wanted, Action<uint, UdpBind> visit)
    {
        byte[]? table = ReadTable(tcp: false, AF_INET6, out int length);
        if (table == null) return;
        ReadOnlySpan<byte> span = table.AsSpan(0, length);
        if (!TryReadHeader(span, out int count)) return;

        for (int i = 0; i < count; i++)
        {
            int offset = 4 + i * UdpRow6Size;
            if (offset + UdpRow6Size > length) return;
            ReadOnlySpan<byte> row = span.Slice(offset, UdpRow6Size);

            uint pid = BinaryPrimitives.ReadUInt32LittleEndian(row.Slice(24, 4));
            if (!wanted(pid)) continue;

            visit(pid, new UdpBind(
                new IPAddress(row.Slice(0, 16)),
                PortFromDword(BinaryPrimitives.ReadUInt32LittleEndian(row.Slice(20, 4)))));
        }
    }
}
