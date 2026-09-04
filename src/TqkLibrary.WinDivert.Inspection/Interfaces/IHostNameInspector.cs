using System;
using System.Threading;
using System.Threading.Tasks;

namespace TqkLibrary.WinDivert.Inspection.Interfaces;

/// <summary>
/// Peeks the first flight a client sends and reports the host name it asked for, leaving the
/// stream untouched so the caller can forward the connection verbatim afterwards.
/// </summary>
public interface IHostNameInspector
{
    /// <summary>
    /// Returns the name, or null when the client revealed none.
    /// </summary>
    /// <remarks>
    /// The peek blocks until the client sends its first bytes, so protocols where the SERVER
    /// speaks first (SMTP, FTP, SSH) would stall here — pass a <paramref name="peekTimeout"/> for
    /// those, and treat null as "route by address instead".
    /// </remarks>
    Task<string?> TryReadHostNameAsync(
        PeekableStream stream,
        TimeSpan? peekTimeout = null,
        CancellationToken cancellationToken = default);
}
