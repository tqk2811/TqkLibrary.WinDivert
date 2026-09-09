using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using TqkLibrary.WinDivert.Inspection;
using TqkLibrary.WinDivert.Redirect;
using TqkLibrary.WinDivert.Redirect.Interfaces;
using TqkLibrary.WinDivert.Redirect.Models;
using Xunit;

namespace TqkLibrary.WinDivert.Tests;

/// <summary>
/// What has to happen to a redirected connection when redirection is switched off: the process on
/// the other end must find out. Neither of these needs the driver, so they run without elevation.
/// </summary>
public class RelayTeardownTests
{
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(15);

    /// <summary>
    /// The client stream is two decorators deep over the socket, and cancelling a transfer closes
    /// it by disposing that outermost decorator. A decorator that swallowed Dispose left the
    /// socket open and the transfer running.
    /// </summary>
    [Fact]
    public void DisposingTheClientStreamDecoratorsClosesTheSocket()
    {
        var inner = new ClosableStream();
        var stream = new PeekableStream(new CountingStream(inner, new ConnectionStatistics()));

        stream.Dispose();

        Assert.True(inner.IsDisposed);
    }

    /// <summary>
    /// A copy loop parked in a read wakes only because the socket under it was closed — which is
    /// the whole reason the decorators must pass Dispose on.
    /// </summary>
    [Fact]
    public async Task DisposingTheClientStreamEndsAReadAlreadyParkedOnIt()
    {
        using var pair = await SocketPair.ConnectAsync();
        var stream = new PeekableStream(new CountingStream(pair.Accepted.GetStream(), new ConnectionStatistics()));

        Task<int> parked = stream.ReadAsync(new byte[16], 0, 16);
        Assert.False(parked.IsCompleted, "the peer has sent nothing, so the read must still be waiting");

        stream.Dispose();

        await Assert.ThrowsAnyAsync<Exception>(() => parked.WaitAsync(Patience));
    }

    /// <summary>
    /// Disposing the relay resets what it has already accepted, instead of leaving each connection
    /// to notice a cancelled token from inside a read it is parked in. The reset has to leave while
    /// the NAT stage is still up to carry it back to the process, so it cannot wait for handlers.
    /// </summary>
    [Fact]
    public async Task DisposingTheRelayResetsAConnectionItHasAccepted()
    {
        var nat = new SingleEntryNatTable();
        // A handler that never returns AND never looks at its token: exactly the case Dispose has
        // to survive. A transfer parked in a socket read is this — the read comes back when the
        // socket is closed, not when a token is cancelled — so a teardown that only cancels and
        // then waits for handlers to hand their sockets back waits for something that never comes.
        var relay = new TcpRelayServer(
            nat, (_, _) => new TaskCompletionSource<object?>().Task, NullLogger<TcpRelayServer>.Instance);
        relay.Start();

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, relay.Port);
        nat.Entry = EntryFor((ushort)((IPEndPoint)client.Client.LocalEndPoint!).Port);

        NetworkStream stream = client.GetStream();
        // Give the relay's accept loop the moment it needs to take the connection on.
        await WaitUntilAsync(() => relay.AcceptedCount > 0);

        relay.Dispose();

        // Read returns 0 on an orderly close and throws on a reset; either says the socket is gone,
        // and "still waiting" — which is what the old teardown left behind — says it is not.
        Task<int> read = stream.ReadAsync(new byte[16], 0, 16);
        try { Assert.Equal(0, await read.WaitAsync(Patience)); }
        catch (IOException) { }
        catch (SocketException) { }
    }

    private static NatEntry EntryFor(ushort sourcePort)
        => new NatEntry(
            pid: 1, protocol: 6,
            origSrc: IPAddress.Loopback, origSrcPort: sourcePort,
            origDst: IPAddress.Parse("203.0.113.9"), origDstPort: 443,
            ifIdx: 0, subIfIdx: 0);

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        DateTime deadline = DateTime.UtcNow + Patience;
        while (!condition())
        {
            Assert.True(DateTime.UtcNow < deadline, "the relay never accepted the connection");
            await Task.Delay(10).ConfigureAwait(false);
        }
    }

    /// <summary>A stream that only records whether it was disposed.</summary>
    private sealed class ClosableStream : Stream
    {
        public bool IsDisposed { get; private set; }

        public override bool CanRead => !IsDisposed;
        public override bool CanSeek => false;
        public override bool CanWrite => !IsDisposed;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => 0;
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) { }

        protected override void Dispose(bool disposing)
        {
            IsDisposed = true;
            base.Dispose(disposing);
        }
    }

    /// <summary>The one flow the relay is told about, so the accepted socket resolves to something.</summary>
    private sealed class SingleEntryNatTable : INatTable
    {
        public NatEntry? Entry { get; set; }

        public int Count => Entry == null ? 0 : 1;
        public bool Upsert(NatEntry entry) { Entry = entry; return true; }
        public NatEntry? Find(byte protocol, ushort srcPort, bool isIpv6)
            => Entry != null && Entry.OriginalSourcePort == srcPort ? Entry : null;
        public bool Remove(byte protocol, ushort srcPort, bool isIpv6) { Entry = null; return true; }
        public void MarkClosed(byte protocol, ushort srcPort, bool isIpv6) { }
    }

    /// <summary>A connected pair of loopback sockets, both closed together.</summary>
    private sealed class SocketPair : IDisposable
    {
        private readonly TcpListener _listener;

        private SocketPair(TcpListener listener, TcpClient connected, TcpClient accepted)
        {
            _listener = listener;
            Connected = connected;
            Accepted = accepted;
        }

        public TcpClient Connected { get; }
        public TcpClient Accepted { get; }

        public static async Task<SocketPair> ConnectAsync()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var connected = new TcpClient();
            await connected.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port).ConfigureAwait(false);
            TcpClient accepted = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
            return new SocketPair(listener, connected, accepted);
        }

        public void Dispose()
        {
            try { Connected.Close(); } catch { }
            try { Accepted.Close(); } catch { }
            try { _listener.Stop(); } catch { }
        }
    }
}
