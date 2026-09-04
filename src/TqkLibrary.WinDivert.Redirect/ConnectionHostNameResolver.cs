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
/// </remarks>
public sealed class ConnectionHostNameResolver : IConnectionHostNameResolver
{
    private readonly IHostNameInspector _inspector;
    private readonly IReverseDnsTable? _reverseDns;

    /// <param name="reverseDns">
    /// Optional. Without it, a connection carrying neither SNI nor a Host header simply has no
    /// name — which is the honest answer, just a less useful one.
    /// </param>
    public ConnectionHostNameResolver(IHostNameInspector inspector, IReverseDnsTable? reverseDns = null)
    {
        _inspector = inspector ?? throw new ArgumentNullException(nameof(inspector));
        _reverseDns = reverseDns;
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
        if (!string.IsNullOrEmpty(peeked)) return peeked;

        return _reverseDns?.Resolve(connection.OriginalDestination.Address);
    }
}
