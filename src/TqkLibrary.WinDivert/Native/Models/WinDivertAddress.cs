using System.Runtime.InteropServices;

namespace TqkLibrary.WinDivert.Native.Models;

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
