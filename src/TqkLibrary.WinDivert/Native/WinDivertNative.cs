using System;
using System.Runtime.InteropServices;

namespace TqkLibrary.WinDivert.Native;

/// <summary>
/// Raw bindings to WinDivert.dll.
/// </summary>
/// <remarks>
/// Every entry point that takes a handle takes the <see cref="WinDivertSafeHandle"/> itself, not
/// the <see cref="IntPtr"/> inside it. That is what makes the marshaller count references across
/// the call, so a handle cannot be closed while another thread is parked inside the driver. Passing
/// a bare pointer instead would let a Dispose on one thread hand the kernel a handle number it has
/// already reissued to something else — an error that no managed catch can see.
/// </remarks>
internal static class WinDivertNative
{
    private const string Dll = "WinDivert.dll";

    [DllImport(Dll, EntryPoint = "WinDivertOpen", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true, SetLastError = true)]
    public static extern WinDivertSafeHandle Open(
        [MarshalAs(UnmanagedType.LPStr)] string filter,
        WinDivertLayer layer,
        short priority,
        WinDivertOpenFlags flags);

    [DllImport(Dll, EntryPoint = "WinDivertRecv", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern bool Recv(
        WinDivertSafeHandle handle,
        IntPtr pPacket,
        uint packetLen,
        out uint pRecvLen,
        ref WinDivertAddress pAddr);

    [DllImport(Dll, EntryPoint = "WinDivertRecvEx", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern bool RecvEx(
        IntPtr handle,
        IntPtr pPacket,
        uint packetLen,
        out uint pRecvLen,
        ulong flags,
        IntPtr pAddr,
        ref uint pAddrLen,
        IntPtr lpOverlapped);

    [DllImport(Dll, EntryPoint = "WinDivertSend", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern bool Send(
        WinDivertSafeHandle handle,
        IntPtr pPacket,
        uint packetLen,
        out uint pSendLen,
        ref WinDivertAddress pAddr);

    /// <summary>
    /// Takes the raw pointer, because it is called from <see cref="WinDivertSafeHandle.ReleaseHandle"/>
    /// where the SafeHandle is already finished and passing it back in would recurse.
    /// </summary>
    [DllImport(Dll, EntryPoint = "WinDivertClose", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern bool Close(IntPtr handle);

    [DllImport(Dll, EntryPoint = "WinDivertShutdown", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern bool Shutdown(WinDivertSafeHandle handle, WinDivertShutdown how);

    [DllImport(Dll, EntryPoint = "WinDivertSetParam", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern bool SetParam(WinDivertSafeHandle handle, WinDivertParam param, ulong value);

    [DllImport(Dll, EntryPoint = "WinDivertGetParam", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern bool GetParam(WinDivertSafeHandle handle, WinDivertParam param, out ulong value);

    [DllImport(Dll, EntryPoint = "WinDivertHelperCalcChecksums", CallingConvention = CallingConvention.Cdecl)]
    public static extern bool HelperCalcChecksums(
        IntPtr pPacket,
        uint packetLen,
        ref WinDivertAddress pAddr,
        WinDivertChecksumFlags flags);

    [DllImport(Dll, EntryPoint = "WinDivertHelperCompileFilter", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
    public static extern bool HelperCompileFilter(
        [MarshalAs(UnmanagedType.LPStr)] string filter,
        WinDivertLayer layer,
        IntPtr @object,
        uint objLen,
        out IntPtr errorStr,
        out uint errorPos);

    [DllImport(Dll, EntryPoint = "WinDivertHelperNtohs", CallingConvention = CallingConvention.Cdecl)]
    public static extern ushort Ntohs(ushort x);

    [DllImport(Dll, EntryPoint = "WinDivertHelperHtons", CallingConvention = CallingConvention.Cdecl)]
    public static extern ushort Htons(ushort x);
}
