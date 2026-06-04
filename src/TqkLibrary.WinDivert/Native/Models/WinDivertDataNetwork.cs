using System.Runtime.InteropServices;

namespace TqkLibrary.WinDivert.Native.Models;

// Mirrors WINDIVERT_DATA_NETWORK (8 bytes)
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct WinDivertDataNetwork
{
    public uint IfIdx;
    public uint SubIfIdx;
}
