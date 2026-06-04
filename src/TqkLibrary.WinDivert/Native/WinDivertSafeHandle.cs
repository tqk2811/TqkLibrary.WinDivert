using System;
using Microsoft.Win32.SafeHandles;

namespace TqkLibrary.WinDivert.Native;

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
