using System.Runtime.InteropServices;

namespace TqkLibrary.WinDivert.Native.Models;

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
