using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace TqkLibrary.WinDivert.Native;

public sealed class WinDivertHandle : IDisposable
{
    private readonly WinDivertSafeHandle _handle;

    public WinDivertLayer Layer { get; }
    public string Filter { get; }

    internal IntPtr DangerousHandle => _handle.DangerousGetHandle();

    private WinDivertHandle(WinDivertSafeHandle handle, WinDivertLayer layer, string filter)
    {
        _handle = handle;
        Layer = layer;
        Filter = filter;
    }

    public static WinDivertHandle Open(string filter, WinDivertLayer layer, short priority, WinDivertOpenFlags flags)
    {
        if (filter is null) throw new ArgumentNullException(nameof(filter));
        IntPtr raw = WinDivertNative.Open(filter, layer, priority, flags);
        if (raw == IntPtr.Zero || raw == new IntPtr(-1))
        {
            int err = Marshal.GetLastWin32Error();
            throw new Win32Exception(err, $"WinDivertOpen failed (layer={layer}, filter=\"{filter}\")");
        }
        return new WinDivertHandle(new WinDivertSafeHandle(raw), layer, filter);
    }

    public unsafe bool TryRecv(byte[] buffer, out int length, out WinDivertAddress addr)
    {
        if (buffer is null) throw new ArgumentNullException(nameof(buffer));
        fixed (byte* p = buffer)
        {
            WinDivertAddress a = default;
            bool ok = WinDivertNative.Recv(_handle.DangerousGetHandle(), (IntPtr)p, (uint)buffer.Length, out uint recv, ref a);
            if (!ok)
            {
                length = 0;
                addr = default;
                return false;
            }
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
            return WinDivertNative.Send(_handle.DangerousGetHandle(), (IntPtr)p, (uint)length, out _, ref addr);
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
        if (!WinDivertNative.SetParam(_handle.DangerousGetHandle(), param, value))
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"WinDivertSetParam {param} failed");
    }

    public ulong GetParam(WinDivertParam param)
    {
        if (!WinDivertNative.GetParam(_handle.DangerousGetHandle(), param, out ulong v))
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"WinDivertGetParam {param} failed");
        return v;
    }

    public void Shutdown(WinDivertShutdown how = WinDivertShutdown.Both)
    {
        WinDivertNative.Shutdown(_handle.DangerousGetHandle(), how);
    }

    public void Dispose()
    {
        _handle.Dispose();
    }
}
