using System;

namespace TqkLibrary.WinDivert.Native.Interfaces;

/// <summary>
/// One open handle on the WinDivert driver: a filter, a layer, and the recv/send pair that moves
/// packets (or socket events) across the kernel boundary.
/// </summary>
/// <remarks>
/// An interface rather than a sealed class so the components built on top of it — the packet pump,
/// the socket tracker — can be exercised without the driver installed and without Administrator
/// rights. Every method is thread-safe in the same way the driver is: recv and send may be called
/// concurrently from different threads, two concurrent recvs on one handle may not.
/// </remarks>
public interface IWinDivertHandle : IDisposable
{
    WinDivertLayer Layer { get; }

    /// <summary>The filter expression this handle was opened with. Diagnostics only.</summary>
    string Filter { get; }

    /// <summary>
    /// Blocks until a packet arrives. False means the driver refused this call, and
    /// <paramref name="win32Error"/> says why.
    /// </summary>
    /// <remarks>
    /// The error code is part of the contract because the reasons are not interchangeable. A
    /// shutdown says stop pumping; a packet too large for the buffer says skip this one and carry
    /// on; anything else is a fault worth reporting. A caller that treats them all as "stop" turns
    /// one oversized packet into a silent end to redirection, with every packet after it going out
    /// unproxied and nothing to say so.
    /// </remarks>
    bool TryRecv(byte[] buffer, out int length, out WinDivertAddress addr, out int win32Error);

    /// <summary>Re-injects a packet. False when the kernel refused it (see Marshal.GetLastWin32Error).</summary>
    bool TrySend(byte[] buffer, int length, ref WinDivertAddress addr);

    /// <summary>Recomputes whichever checksums <paramref name="flags"/> asks for, in place.</summary>
    void CalcChecksums(byte[] buffer, int length, ref WinDivertAddress addr, WinDivertChecksumFlags flags = WinDivertChecksumFlags.All);

    void SetParam(WinDivertParam param, ulong value);
    ulong GetParam(WinDivertParam param);

    /// <summary>
    /// Unblocks a pending TryRecv so a pump thread can exit. Always call this before Dispose:
    /// disposing a handle a thread is blocked in is how a shutdown turns into a hang.
    /// </summary>
    void Shutdown(WinDivertShutdown how = WinDivertShutdown.Both);
}
