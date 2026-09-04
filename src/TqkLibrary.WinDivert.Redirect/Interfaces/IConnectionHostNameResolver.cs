using System;
using System.Threading;
using System.Threading.Tasks;

namespace TqkLibrary.WinDivert.Redirect.Interfaces;

/// <summary>
/// Works out which host a redirected connection is for, so a router can decide by name rather than
/// by address.
/// </summary>
public interface IConnectionHostNameResolver
{
    /// <summary>
    /// Returns the host name, or null when the connection reveals none — in which case the caller
    /// routes by IP alone.
    /// </summary>
    /// <param name="peekTimeout">
    /// How long to wait for the client to speak first. Protocols where the SERVER speaks first
    /// (SMTP, FTP, SSH) never send anything to peek at, so without a timeout they stall.
    /// </param>
    Task<string?> TryResolveAsync(
        RedirectedTcpConnection connection,
        TimeSpan? peekTimeout = null,
        CancellationToken cancellationToken = default);
}
