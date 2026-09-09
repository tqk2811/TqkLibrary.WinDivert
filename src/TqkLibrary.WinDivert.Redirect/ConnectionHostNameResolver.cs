using System;
using System.Threading;
using System.Threading.Tasks;

namespace TqkLibrary.WinDivert.Redirect;

/// <summary>
/// Name discovery for a redirected connection, in the order a router should trust it:
/// what the client itself asks for (TLS SNI, then an HTTP Host header), and failing that, what the
/// process resolved just before it connected (the reverse-DNS table).
/// </summary>
/// <remarks>
/// The client's own words come first for a reason: a reverse-DNS answer is a guess about which of
/// the several names sharing an address was meant, while SNI is the name the client typed.
/// <para>
/// A name read from the client is also written BACK into the reverse-DNS table, so the traffic
/// that carries no name of its own — UDP, and QUIC above all — can be recognised by address. That
/// matters because a browser resolving over its own DoH leaves nothing for the DNS sniffer to
/// learn from: without this the table stays empty for that destination, a QUIC flow to it matches
/// no rule at all, and traffic the user asked to be tunnelled leaves direct with the real address
/// on it while the TCP half of the same site rides the tunnel.
/// </para>
/// </remarks>
public sealed class ConnectionHostNameResolver : IConnectionHostNameResolver
{
    /// <summary>
    /// How long a name read from a client is worth by address. Short on purpose: unlike a DNS
    /// answer it carries no TTL, and one address can serve many names — a CDN's does — so the
    /// mapping is a recent observation rather than a fact about the address. Long enough to cover
    /// the QUIC attempt a browser makes right after the TCP connection it learned Alt-Svc from.
    /// </summary>
    public static readonly TimeSpan DefaultLearnedNameLifetime = TimeSpan.FromMinutes(2);

    private readonly IHostNameInspector _inspector;
    private readonly IReverseDnsTable? _reverseDns;
    private readonly TimeSpan _learnedNameLifetime;

    /// <param name="reverseDns">
    /// Optional. Without it, a connection carrying neither SNI nor a Host header simply has no
    /// name — which is the honest answer, just a less useful one — and nothing is learned back.
    /// </param>
    /// <param name="learnedNameLifetime">
    /// How long a name read from a client stays resolvable by address; null uses
    /// <see cref="DefaultLearnedNameLifetime"/>.
    /// </param>
    public ConnectionHostNameResolver(
        IHostNameInspector inspector,
        IReverseDnsTable? reverseDns = null,
        TimeSpan? learnedNameLifetime = null)
    {
        _inspector = inspector ?? throw new ArgumentNullException(nameof(inspector));
        _reverseDns = reverseDns;
        _learnedNameLifetime = learnedNameLifetime ?? DefaultLearnedNameLifetime;
    }

    public async Task<string?> TryResolveAsync(
        RedirectedTcpConnection connection,
        TimeSpan? peekTimeout = null,
        CancellationToken cancellationToken = default)
    {
        if (connection is null) throw new ArgumentNullException(nameof(connection));

        // The peek leaves the bytes in the stream, so the connection is forwarded unchanged after.
        string? peeked = await _inspector
            .TryReadHostNameAsync(connection.ClientStream, peekTimeout, cancellationToken)
            .ConfigureAwait(false);
        if (!string.IsNullOrEmpty(peeked))
        {
            _reverseDns?.Add(connection.OriginalDestination.Address, peeked!, _learnedNameLifetime);
            return peeked;
        }

        return _reverseDns?.Resolve(connection.OriginalDestination.Address);
    }
}
