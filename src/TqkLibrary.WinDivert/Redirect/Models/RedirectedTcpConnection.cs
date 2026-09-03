using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace TqkLibrary.WinDivert.Redirect.Models;

// Given to the caller when a redirected TCP connection is accepted by the local relay.
//
// The relay does NOT open the upstream socket: the caller decides where the bytes go (an upstream
// proxy, a VPN tunnel, or the real destination via RelayDirectAsync). Connecting eagerly would
// leak the real client IP to the destination even for connections that end up going through a
// proxy, and would burn a socket per connection for nothing.
//
// ClientStream is wrapped in a CountingStream, so Statistics stays accurate whichever path the
// caller picks.
public sealed class RedirectedTcpConnection : IDisposable
{
    private readonly PeekableStream _clientStream;
    private TcpClient? _directUpstream;

    public uint ProcessId { get; }
    public IPEndPoint OriginalSource { get; }
    public IPEndPoint OriginalDestination { get; }

    public TcpClient ClientTcp { get; }

    // Bytes coming FROM / going TO the target process. Counted, and peekable so a handler can read
    // the TLS ClientHello (SNI) or the HTTP request line before deciding where to route — the
    // peeked bytes are still delivered upstream afterwards.
    public PeekableStream ClientStream => _clientStream;

    public ConnectionStatistics Statistics { get; } = new ConnectionStatistics();

    public RedirectedTcpConnection(uint pid, IPEndPoint origSrc, IPEndPoint origDst, TcpClient client)
    {
        ProcessId = pid;
        OriginalSource = origSrc;
        OriginalDestination = origDst;
        ClientTcp = client ?? throw new ArgumentNullException(nameof(client));
        _clientStream = new PeekableStream(new CountingStream(client.GetStream(), Statistics));
    }

    // Opens a socket to the ORIGINAL destination and pipes both directions verbatim — the
    // pre-proxy behaviour, kept for pass-through/observe scenarios. The upstream socket is owned
    // by this connection and closed on Dispose.
    public async Task RelayDirectAsync(CancellationToken ct = default)
    {
        if (_directUpstream != null) throw new InvalidOperationException("Direct upstream already opened");
        var upstream = new TcpClient();
        _directUpstream = upstream;
        await upstream.ConnectAsync(OriginalDestination.Address, OriginalDestination.Port).ConfigureAwait(false);
        await RelayToAsync(upstream.GetStream(), ct).ConfigureAwait(false);
    }

    // Pipes both directions between the process and an upstream stream the caller opened
    // (proxy tunnel, VPN stack, ...). The upstream stream is NOT disposed here — its owner is
    // whoever created it.
    public async Task RelayToAsync(Stream upstream, CancellationToken ct = default)
    {
        if (upstream is null) throw new ArgumentNullException(nameof(upstream));
        Task c2u = CopyAsync(ClientStream, upstream, ct);
        Task u2c = CopyAsync(upstream, ClientStream, ct);
        await Task.WhenAny(c2u, u2c).ConfigureAwait(false);
    }

    private static async Task CopyAsync(Stream from, Stream to, CancellationToken ct)
    {
        byte[] buf = new byte[16 * 1024];
        try
        {
            while (!ct.IsCancellationRequested)
            {
                int n = await from.ReadAsync(buf, 0, buf.Length, ct).ConfigureAwait(false);
                if (n <= 0) return;
                await to.WriteAsync(buf, 0, n, ct).ConfigureAwait(false);
                await to.FlushAsync(ct).ConfigureAwait(false);
            }
        }
        catch
        {
            // swallow; the caller observes completion via the returned task
        }
    }

    public void Dispose()
    {
        Statistics.MarkEnded();
        try { ClientTcp.Close(); } catch { }
        try { _directUpstream?.Close(); } catch { }
    }
}
