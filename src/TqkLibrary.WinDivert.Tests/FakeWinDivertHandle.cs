using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using TqkLibrary.WinDivert.Native.Enums;
using TqkLibrary.WinDivert.Native.Interfaces;
using TqkLibrary.WinDivert.Native.Models;

namespace TqkLibrary.WinDivert.Tests;

/// <summary>
/// A handle that fails the way the driver's does once it has been closed, and remembers that it
/// happened.
/// </summary>
/// <remarks>
/// The real one wraps a <see cref="System.Runtime.InteropServices.SafeHandle"/>: a call on a
/// disposed handle throws ObjectDisposedException out of DangerousAddRef, and that throw lands on a
/// pump thread nothing is waiting on, where it vanishes. So the tests assert on
/// <see cref="UseAfterClose"/> rather than on an exception they would never see.
///
/// No driver and no elevation are involved — nothing here opens a real handle.
/// </remarks>
internal sealed class FakeWinDivertHandle : IWinDivertHandle
{
    private const int ErrorNoData = 232;

    private readonly ManualResetEventSlim _stopAsked = new ManualResetEventSlim(false);
    private int _disposed;
    private int _useAfterClose;
    private int _recvCalls;
    private int _sendCalls;
    private int _lastEventPending;

    public FakeWinDivertHandle(string filter = "true", WinDivertLayer layer = WinDivertLayer.Socket)
    {
        Filter = filter;
        Layer = layer;
    }

    public WinDivertLayer Layer { get; }
    public string Filter { get; }

    /// <summary>
    /// What a recv does while nothing has asked the handle to stop: block, the way a quiet driver
    /// does, or hand back events one after another.
    /// </summary>
    /// <remarks>
    /// Streaming keeps the pump calling back into the handle, which is what a test of "who is
    /// allowed to close this" needs: a loop that stops on its own would hide the second call, and
    /// the second call is where the bug lives.
    /// </remarks>
    public bool StreamsEvents { get; init; }

    /// <summary>
    /// How long a recv keeps running after it has been asked to stop. Longer than the second a
    /// disposer waits is the case that matters: that is when the old code gave up and closed the
    /// handle anyway.
    /// </summary>
    public TimeSpan LingerAfterStop { get; init; } = TimeSpan.Zero;

    /// <summary>
    /// Whether the recv that outlives the shutdown hands back one final event, so the pump runs a
    /// whole iteration — and calls back into the handle — on its way out.
    /// </summary>
    public bool DeliversOneLastEvent
    {
        init => _lastEventPending = value ? 1 : 0;
    }

    /// <summary>Calls made after the handle was closed. The assertion of every test here.</summary>
    public int UseAfterClose => Volatile.Read(ref _useAfterClose);

    public int RecvCalls => Volatile.Read(ref _recvCalls);

    /// <summary>
    /// Whether the first recv ran on a thread-pool thread. A pump parks in recv for its whole life,
    /// so a pool thread taken here is a pool thread never given back — see BlockingLoop.
    /// </summary>
    public bool? FirstRecvOnThreadPoolThread { get; private set; }

    /// <summary>
    /// Sends attempted, counted before the closed check rather than after.
    /// </summary>
    /// <remarks>
    /// This is what a test waits on, and waiting on the close instead is a trap worth naming: the
    /// close is what the buggy disposer does *early*, at the one-second mark, while the pump's
    /// offending call comes later, when its slow recv finally returns. A test that asserted as soon
    /// as the handle was closed therefore passed against the very code it was written to catch.
    /// </remarks>
    public int SendCalls => Volatile.Read(ref _sendCalls);

    public bool IsClosed => Volatile.Read(ref _disposed) != 0;

    public bool WaitForFirstRecv(TimeSpan timeout) => Until(() => RecvCalls > 0, timeout);

    public bool WaitForSend(TimeSpan timeout) => Until(() => SendCalls > 0, timeout);

    public bool WaitUntilClosed(TimeSpan timeout) => Until(() => IsClosed, timeout);

    private static bool Until(Func<bool> condition, TimeSpan timeout) => SpinWait.SpinUntil(condition, timeout);

    public bool TryRecv(byte[] buffer, out int length, out WinDivertAddress addr, out int win32Error)
    {
        if (Interlocked.Increment(ref _recvCalls) == 1)
            FirstRecvOnThreadPoolThread = Thread.CurrentThread.IsThreadPoolThread;
        ThrowIfClosed();

        length = 0;
        addr = default;

        if (!_stopAsked.IsSet)
        {
            if (!StreamsEvents)
            {
                _stopAsked.Wait();
            }
            else
            {
                // Paced rather than as fast as the machine allows: the point is that the pump keeps
                // calling, not that it spins a core while the test gets to its assertion.
                Thread.Sleep(1);
                win32Error = 0;
                return true;
            }
        }

        if (LingerAfterStop > TimeSpan.Zero) Thread.Sleep(LingerAfterStop);

        if (Interlocked.Exchange(ref _lastEventPending, 0) == 1)
        {
            win32Error = 0;
            return true;
        }

        win32Error = ErrorNoData;
        return false;
    }

    public bool TrySend(byte[] buffer, int length, ref WinDivertAddress addr)
    {
        Interlocked.Increment(ref _sendCalls);
        ThrowIfClosed();
        return true;
    }

    public void CalcChecksums(byte[] buffer, int length, ref WinDivertAddress addr, WinDivertChecksumFlags flags = WinDivertChecksumFlags.All)
        => ThrowIfClosed();

    public void SetParam(WinDivertParam param, ulong value) => ThrowIfClosed();

    public ulong GetParam(WinDivertParam param)
    {
        ThrowIfClosed();
        return 0;
    }

    /// <summary>
    /// Asks the recv to return. Exempt from the use-after-close count on purpose: this is the one
    /// call another thread is meant to make, and a pump that has already left has already closed
    /// the handle, so every caller wraps it in a catch. Counting it would flag the normal ending.
    /// </summary>
    public void Shutdown(WinDivertShutdown how = WinDivertShutdown.Both) => _stopAsked.Set();

    public void Dispose()
    {
        Volatile.Write(ref _disposed, 1);
        // Released here too, so a test that closes a handle without shutting it down first does not
        // leave a pump parked in recv for ever.
        _stopAsked.Set();
    }

    private void ThrowIfClosed()
    {
        if (Volatile.Read(ref _disposed) == 0) return;
        Interlocked.Increment(ref _useAfterClose);
        throw new ObjectDisposedException(nameof(FakeWinDivertHandle));
    }
}

/// <summary>Hands out <see cref="FakeWinDivertHandle"/>s and remembers every one it opened.</summary>
internal sealed class FakeHandleFactory : IWinDivertHandleFactory
{
    private readonly Func<string, FakeWinDivertHandle> _open;
    private readonly ConcurrentQueue<FakeWinDivertHandle> _opened = new ConcurrentQueue<FakeWinDivertHandle>();

    public FakeHandleFactory(Func<string, FakeWinDivertHandle>? open = null)
    {
        _open = open ?? (filter => new FakeWinDivertHandle(filter));
    }

    public IReadOnlyList<FakeWinDivertHandle> Opened => _opened.ToArray();

    public IWinDivertHandle Open(string filter, WinDivertLayer layer, short priority, WinDivertOpenFlags flags)
    {
        FakeWinDivertHandle handle = _open(filter);
        _opened.Enqueue(handle);
        return handle;
    }
}
