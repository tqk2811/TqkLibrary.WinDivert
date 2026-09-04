using System;
using System.Threading;
using System.Threading.Tasks;

namespace TqkLibrary.WinDivert.SecureDns.Interfaces;

/// <summary>
/// Answers a DNS query that was taken away from the target process, over some transport the
/// process itself could not use.
/// </summary>
public interface IDnsResolver : IDisposable
{
    /// <summary>Where the queries go. Diagnostics and logging only.</summary>
    Uri Endpoint { get; }

    /// <summary>
    /// Takes a raw DNS query in wire format and returns the raw response, or null on any failure.
    /// </summary>
    /// <remarks>
    /// Failing to null rather than throwing is the fail-closed choice: the caller has already
    /// dropped the original query, so a null answer just lets the client time out and retry.
    /// Nothing leaks out unproxied either way.
    /// </remarks>
    Task<byte[]?> ResolveAsync(byte[] dnsWireQuery, CancellationToken ct);
}
