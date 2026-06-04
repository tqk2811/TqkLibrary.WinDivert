using System.Net;
using System.Runtime.InteropServices;

namespace TqkLibrary.WinDivert.Native.Models;

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
