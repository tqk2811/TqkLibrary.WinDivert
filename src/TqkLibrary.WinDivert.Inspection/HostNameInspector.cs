using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace TqkLibrary.WinDivert.Inspection;

/// <summary>
/// Asks each of its parsers, in order, what host name the client is after — and stops peeking the
/// moment none of them can still recognise the traffic.
/// </summary>
/// <remarks>
/// The read pattern matters: peek a chunk, try to parse, and only ask for more when a parser says
/// the message is merely incomplete. A client sends its first flight and then waits for the
/// server, so reading past the end of that flight would block until the peek times out — which
/// on a fast path is the difference between microseconds and seconds.
/// </remarks>
public sealed class HostNameInspector : IHostNameInspector
{
    private readonly IHostNameParser[] _parsers;
    private readonly int _peekSize;

    /// <param name="parsers">
    /// Tried in order, so put the most trustworthy first: TLS SNI is what the client itself says
    /// it wants, an HTTP Host header is the same for cleartext.
    /// </param>
    public HostNameInspector(IEnumerable<IHostNameParser> parsers)
    {
        if (parsers is null) throw new ArgumentNullException(nameof(parsers));
        _parsers = parsers.ToArray();
        if (_parsers.Length == 0) throw new ArgumentException("At least one parser is required", nameof(parsers));
        _peekSize = _parsers.Max(p => p.RecommendedPeekSize);
    }

    /// <summary>The default set: TLS ClientHello first, then plaintext HTTP.</summary>
    public static HostNameInspector CreateDefault()
        => new HostNameInspector(new IHostNameParser[] { new TlsClientHelloParser(), new HttpHostParser() });

    public async Task<string?> TryReadHostNameAsync(
        PeekableStream stream,
        TimeSpan? peekTimeout = null,
        CancellationToken cancellationToken = default)
    {
        if (stream is null) throw new ArgumentNullException(nameof(stream));

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (peekTimeout.HasValue) timeoutCts.CancelAfter(peekTimeout.Value);

        try
        {
            int available = 0;
            int previous = -1;
            while (available < _peekSize && available != previous)
            {
                previous = available;
                available = await stream.PeekAsync(_peekSize, timeoutCts.Token).ConfigureAwait(false);
                if (available <= 0) return null;

                byte[] chunk = stream.PeekBuffer;
                bool anyRecognised = false;
                foreach (IHostNameParser parser in _parsers)
                {
                    if (parser.TryReadHostName(chunk, available, out string name) && !string.IsNullOrEmpty(name))
                        return name;
                    anyRecognised |= parser.CanParse(chunk, available);
                }

                // No parser recognises the protocol at all: more bytes cannot change that.
                if (!anyRecognised) return null;
            }
        }
        catch (OperationCanceledException)
        {
            // The client said nothing in time (or the caller cancelled) — the caller falls back to
            // whatever else it knows about the destination.
        }
        catch (Exception)
        {
            // Any parse or I/O surprise just means "no name". Never fail a connection over this.
        }
        return null;
    }
}
