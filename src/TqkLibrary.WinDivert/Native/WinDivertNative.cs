using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace TqkLibrary.WinDivert.Native;

internal static class WinDivertNative
{
    private const string Dll = "WinDivert.dll";

    [DllImport(Dll, EntryPoint = "WinDivertOpen", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true, SetLastError = true)]
    public static extern IntPtr Open(
        [MarshalAs(UnmanagedType.LPStr)] string filter,
        WinDivertLayer layer,
        short priority,
        WinDivertOpenFlags flags);

    [DllImport(Dll, EntryPoint = "WinDivertRecv", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern bool Recv(
        IntPtr handle,
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
        IntPtr handle,
        IntPtr pPacket,
        uint packetLen,
        out uint pSendLen,
        ref WinDivertAddress pAddr);

    [DllImport(Dll, EntryPoint = "WinDivertClose", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern bool Close(IntPtr handle);

    [DllImport(Dll, EntryPoint = "WinDivertShutdown", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern bool Shutdown(IntPtr handle, WinDivertShutdown how);

    [DllImport(Dll, EntryPoint = "WinDivertSetParam", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern bool SetParam(IntPtr handle, WinDivertParam param, ulong value);

    [DllImport(Dll, EntryPoint = "WinDivertGetParam", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern bool GetParam(IntPtr handle, WinDivertParam param, out ulong value);

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

internal sealed class WinDivertSafeHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public WinDivertSafeHandle() : base(true) { }

    internal WinDivertSafeHandle(IntPtr handle) : base(true)
    {
        SetHandle(handle);
    }

    protected override bool ReleaseHandle()
    {
        return WinDivertNative.Close(handle);
    }
}
