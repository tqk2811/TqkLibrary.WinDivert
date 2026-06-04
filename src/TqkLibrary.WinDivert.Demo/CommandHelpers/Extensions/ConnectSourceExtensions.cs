using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TqkLibrary.Proxy.Interfaces;
using TqkLibrary.Proxy.StreamHelpers;

namespace TqkLibrary.WinDivert.Demo.CommandHelpers.Extensions;

// Convenience wrapper around IConnectSource that the demo uses to forward a client stream
// through an already-connected tunnel. TqkLibrary.Proxy itself only exposes the raw Stream via
// GetStreamAsync, so every caller would otherwise repeat the same StreamTransferHelper boilerplate.
// Move this into TqkLibrary.Proxy when the pattern stabilises.
internal static class ConnectSourceExtensions
{
    public static async Task ForwardAsync(
        this IConnectSource source,
        Stream clientStream,
        Guid tunnelId,
        ILoggerFactory? loggerFactory = null,
        string clientName = "client",
        string proxyName = "proxy",
        CancellationToken cancellationToken = default)
    {
        if (source is null) throw new ArgumentNullException(nameof(source));
        if (clientStream is null) throw new ArgumentNullException(nameof(clientStream));

        Stream proxyStream = await source.GetStreamAsync(cancellationToken).ConfigureAwait(false);
        await new StreamTransferHelper(clientStream, proxyStream, tunnelId, loggerFactory)
            .DebugName(clientName, proxyName)
            .WaitUntilDisconnect(cancellationToken)
            .ConfigureAwait(false);
    }
}
