using System.Net;
using System.Runtime.InteropServices;

namespace TqkLibrary.WinDivert.Native;

// Mirrors WINDIVERT_DATA_NETWORK (8 bytes)
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct WinDivertDataNetwork
{
    public uint IfIdx;
    public uint SubIfIdx;
}

// Mirrors WINDIVERT_DATA_FLOW. Address fields are a 4-word array in C; flattened to 4 uints
// here so the struct stays blittable without fixed-buffer access rules getting in the way.
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct WinDivertDataFlow
{
    public ulong EndpointId;
    public ulong ParentEndpointId;
    public uint ProcessId;
    public uint LocalAddr0;
    public uint LocalAddr1;
    public uint LocalAddr2;
    public uint LocalAddr3;
    public uint RemoteAddr0;
    public uint RemoteAddr1;
    public uint RemoteAddr2;
    public uint RemoteAddr3;
    public ushort LocalPort;
    public ushort RemotePort;
    public byte Protocol;

    public IPAddress GetLocalAddress(bool isIpv6)
        => AddressHelper.FromWords(LocalAddr0, LocalAddr1, LocalAddr2, LocalAddr3, isIpv6);

    public IPAddress GetRemoteAddress(bool isIpv6)
        => AddressHelper.FromWords(RemoteAddr0, RemoteAddr1, RemoteAddr2, RemoteAddr3, isIpv6);
}

// Mirrors WINDIVERT_DATA_SOCKET — same shape as FLOW.
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct WinDivertDataSocket
{
    public ulong EndpointId;
    public ulong ParentEndpointId;
    public uint ProcessId;
    public uint LocalAddr0;
    public uint LocalAddr1;
    public uint LocalAddr2;
    public uint LocalAddr3;
    public uint RemoteAddr0;
    public uint RemoteAddr1;
    public uint RemoteAddr2;
    public uint RemoteAddr3;
    public ushort LocalPort;
    public ushort RemotePort;
    public byte Protocol;

    public IPAddress GetLocalAddress(bool isIpv6)
        => AddressHelper.FromWords(LocalAddr0, LocalAddr1, LocalAddr2, LocalAddr3, isIpv6);

    public IPAddress GetRemoteAddress(bool isIpv6)
        => AddressHelper.FromWords(RemoteAddr0, RemoteAddr1, RemoteAddr2, RemoteAddr3, isIpv6);
}

// Mirrors WINDIVERT_DATA_REFLECT
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct WinDivertDataReflect
{
    public long Timestamp;
    public uint ProcessId;
    public WinDivertLayer Layer;
    public ulong Flags;
    public short Priority;
}

// WINDIVERT_ADDRESS v2: total 80 bytes. Timestamp(8) + Flags(4) + Reserved2(4) + union(64).
[StructLayout(LayoutKind.Explicit, Size = 80)]
public struct WinDivertAddress
{
    [FieldOffset(0)] public long Timestamp;
    [FieldOffset(8)] public uint FlagsPacked;
    [FieldOffset(12)] public uint Reserved2;
    [FieldOffset(16)] public WinDivertDataNetwork Network;
    [FieldOffset(16)] public WinDivertDataFlow Flow;
    [FieldOffset(16)] public WinDivertDataSocket Socket;
    [FieldOffset(16)] public WinDivertDataReflect Reflect;

    // Bit layout (LSB first):
    //  [0..7]   Layer
    //  [8..15]  Event
    //  [16]     Sniffed
    //  [17]     Outbound
    //  [18]     Loopback
    //  [19]     Impostor
    //  [20]     IPv6
    //  [21]     IPChecksum
    //  [22]     TCPChecksum
    //  [23]     UDPChecksum
    //  [24..31] Reserved1

    public WinDivertLayer Layer
    {
        get => (WinDivertLayer)(FlagsPacked & 0xFFu);
        set => FlagsPacked = (FlagsPacked & ~0xFFu) | ((uint)value & 0xFFu);
    }

    public WinDivertEvent Event
    {
        get => (WinDivertEvent)((FlagsPacked >> 8) & 0xFFu);
        set => FlagsPacked = (FlagsPacked & ~(0xFFu << 8)) | (((uint)value & 0xFFu) << 8);
    }

    private bool GetFlag(int bit) => ((FlagsPacked >> bit) & 1u) != 0u;
    private void SetFlag(int bit, bool on)
    {
        if (on) FlagsPacked |= 1u << bit;
        else FlagsPacked &= ~(1u << bit);
    }

    public bool Sniffed { get => GetFlag(16); set => SetFlag(16, value); }
    public bool Outbound { get => GetFlag(17); set => SetFlag(17, value); }
    public bool Loopback { get => GetFlag(18); set => SetFlag(18, value); }
    public bool Impostor { get => GetFlag(19); set => SetFlag(19, value); }
    public bool IPv6 { get => GetFlag(20); set => SetFlag(20, value); }
    public bool IPChecksum { get => GetFlag(21); set => SetFlag(21, value); }
    public bool TCPChecksum { get => GetFlag(22); set => SetFlag(22, value); }
    public bool UDPChecksum { get => GetFlag(23); set => SetFlag(23, value); }
}

internal static class AddressHelper
{
    public static IPAddress FromWords(uint w0, uint w1, uint w2, uint w3, bool isIpv6)
    {
        if (!isIpv6)
        {
            // WinDivert exposes IPv4 in host byte order; convert to network-order bytes for IPAddress.
            byte[] b = new byte[4];
            b[0] = (byte)(w0 >> 24);
            b[1] = (byte)(w0 >> 16);
            b[2] = (byte)(w0 >> 8);
            b[3] = (byte)w0;
            return new IPAddress(b);
        }
        byte[] ip6 = new byte[16];
        WriteWord(ip6, 0, w0);
        WriteWord(ip6, 4, w1);
        WriteWord(ip6, 8, w2);
        WriteWord(ip6, 12, w3);
        return new IPAddress(ip6);
    }

    private static void WriteWord(byte[] dst, int at, uint w)
    {
        dst[at + 0] = (byte)(w >> 24);
        dst[at + 1] = (byte)(w >> 16);
        dst[at + 2] = (byte)(w >> 8);
        dst[at + 3] = (byte)w;
    }
}
