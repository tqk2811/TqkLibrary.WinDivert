using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace TqkLibrary.WinDivert.Native;

public sealed class WinDivertHandle : IWinDivertHandle
{
    private readonly WinDivertSafeHandle _handle;

    public WinDivertLayer Layer { get; }
    public string Filter { get; }

    private WinDivertHandle(WinDivertSafeHandle handle, WinDivertLayer layer, string filter)
    {
        _handle = handle;
        Layer = layer;
        Filter = filter;
    }

    public static WinDivertHandle Open(string filter, WinDivertLayer layer, short priority, WinDivertOpenFlags flags)
    {
        if (filter is null) throw new ArgumentNullException(nameof(filter));

        // The marshaller builds the SafeHandle inside the call, so there is no instant where the
        // raw handle exists with nobody owning it.
        WinDivertSafeHandle handle = WinDivertNative.Open(filter, layer, priority, flags);
        if (handle.IsInvalid)
        {
            int err = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(err, $"WinDivertOpen failed (layer={layer}, filter=\"{filter}\")");
        }
        return new WinDivertHandle(handle, layer, filter);
    }

    public unsafe bool TryRecv(byte[] buffer, out int length, out WinDivertAddress addr, out int win32Error)
    {
        if (buffer is null) throw new ArgumentNullException(nameof(buffer));
        fixed (byte* p = buffer)
        {
            WinDivertAddress a = default;
            bool ok = WinDivertNative.Recv(_handle, (IntPtr)p, (uint)buffer.Length, out uint recv, ref a);
            if (!ok)
            {
                // Read it here, before anything else on this thread can overwrite it.
                win32Error = Marshal.GetLastWin32Error();
                length = 0;
                addr = default;
                return false;
            }
            win32Error = 0;
            length = (int)recv;
            addr = a;
            return true;
        }
    }

    public unsafe bool TrySend(byte[] buffer, int length, ref WinDivertAddress addr)
    {
        if (buffer is null) throw new ArgumentNullException(nameof(buffer));
        if ((uint)length > buffer.Length) throw new ArgumentOutOfRangeException(nameof(length));
        fixed (byte* p = buffer)
        {
            return WinDivertNative.Send(_handle, (IntPtr)p, (uint)length, out _, ref addr);
        }
    }

    public unsafe void CalcChecksums(byte[] buffer, int length, ref WinDivertAddress addr, WinDivertChecksumFlags flags = WinDivertChecksumFlags.All)
    {
        fixed (byte* p = buffer)
        {
            WinDivertNative.HelperCalcChecksums((IntPtr)p, (uint)length, ref addr, flags);
        }
    }

    public void SetParam(WinDivertParam param, ulong value)
    {
        if (!WinDivertNative.SetParam(_handle, param, value))
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"WinDivertSetParam {param} failed");
    }

    public ulong GetParam(WinDivertParam param)
    {
        if (!WinDivertNative.GetParam(_handle, param, out ulong v))
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"WinDivertGetParam {param} failed");
        return v;
    }

    public void Shutdown(WinDivertShutdown how = WinDivertShutdown.Both)
    {
        WinDivertNative.Shutdown(_handle, how);
    }

    public void Dispose()
    {
        _handle.Dispose();
    }
}
