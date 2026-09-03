using System;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.WinDivert.Redirect;
using TqkLibrary.WinDivert.SecureDns;

namespace TqkLibrary.WinDivert.Inspection.Extensions;

// Name discovery for a redirected connection, in the order a router should trust it:
//   1. TLS SNI            — what the client itself says it wants
//   2. HTTP Host header   — same, for cleartext HTTP
//   3. reverse DNS table  — what the process resolved just before connecting
// A connection with none of these is routed by IP alone.
public static class RedirectedTcpConnectionExtensions
{
    // Peeks the first flight and returns the host name, or null when the connection reveals none.
    // Peeked bytes stay in the stream, so the caller forwards the connection unchanged afterwards.
    //
    // The peek blocks until the client sends its first bytes; protocols where the SERVER speaks
    // first (SMTP, FTP, SSH) would stall here, so pass a timeout for those.
    public static async Task<string?> TryPeekHostNameAsync(
        this RedirectedTcpConnection connection,
        ReverseDnsTable? reverseDns = null,
        TimeSpan? peekTimeout = null,
        CancellationToken cancellationToken = default)
    {
        if (connection is null) throw new ArgumentNullException(nameof(connection));

        string? peeked = await TryPeekFromWireAsync(connection, peekTimeout, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrEmpty(peeked)) return peeked;

        return reverseDns?.Resolve(connection.OriginalDestination.Address);
    }

    private static async Task<string?> TryPeekFromWireAsync(
        RedirectedTcpConnection connection, TimeSpan? peekTimeout, CancellationToken cancellationToken)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (peekTimeout.HasValue) timeoutCts.CancelAfter(peekTimeout.Value);

        try
        {
            PeekableStream stream = connection.ClientStream;
            int peekSize = Math.Max(TlsClientHelloParser.RecommendedPeekSize, HttpHostParser.RecommendedPeekSize);
            int available = await stream.PeekAsync(peekSize, timeoutCts.Token).ConfigureAwait(false);
            if (available <= 0) return null;

            byte[] buffer = stream.PeekBuffer;
            if (TlsClientHelloParser.TryReadServerName(buffer, available, out string sni)) return sni;
            if (HttpHostParser.TryReadHost(buffer, available, out string host)) return host;
        }
        catch (OperationCanceledException)
        {
            // Client said nothing in time (or the caller cancelled) — fall back to reverse DNS.
        }
        catch (Exception ex)
        {
            // Any parse/IO surprise just means "no name" — the caller falls back to reverse DNS.
            _ = ex;
        }
        return null;
    }
}
