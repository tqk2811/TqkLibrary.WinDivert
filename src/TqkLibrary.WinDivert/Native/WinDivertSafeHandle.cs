using System;
using Microsoft.Win32.SafeHandles;

namespace TqkLibrary.WinDivert.Native;

/// <summary>
/// An open WinDivert driver handle, reference-counted for the length of every call that uses it.
/// </summary>
/// <remarks>
/// The counting is the point. Recv parks a thread inside the driver for as long as it takes a
/// packet to arrive, while shutdown happens on another thread; without a reference held across the
/// call, closing here would leave that thread issuing a DeviceIoControl on a handle number the
/// kernel may already have handed to something else. The parameterless constructor is what the
/// P/Invoke marshaller uses to build one from a returned pointer.
/// </remarks>
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
