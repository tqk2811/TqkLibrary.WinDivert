using System;
using System.Threading;

namespace TqkLibrary.WinDivert.Redirect.Models;

// Byte counters for one redirected TCP connection. Owned by RedirectedTcpConnection and fed by
// the CountingStream wrapper around the client socket, so the numbers are correct no matter how
// the caller moves the bytes (built-in relay, an upstream proxy tunnel, or hand-written I/O).
public sealed class ConnectionStatistics
{
    private long _bytesFromProcess;
    private long _bytesToProcess;

    public DateTime StartedUtc { get; } = DateTime.UtcNow;

    // Set when the connection is disposed; null while the connection is live.
    public DateTime? EndedUtc { get; private set; }

    // Bytes the target process sent (client -> upstream).
    public long BytesFromProcess => Interlocked.Read(ref _bytesFromProcess);

    // Bytes delivered back to the target process (upstream -> client).
    public long BytesToProcess => Interlocked.Read(ref _bytesToProcess);

    public TimeSpan Duration => (EndedUtc ?? DateTime.UtcNow) - StartedUtc;

    internal void AddFromProcess(long count) => Interlocked.Add(ref _bytesFromProcess, count);

    internal void AddToProcess(long count) => Interlocked.Add(ref _bytesToProcess, count);

    internal void MarkEnded() => EndedUtc ??= DateTime.UtcNow;

    public override string ToString()
        => $"up={BytesFromProcess}B down={BytesToProcess}B {Duration.TotalSeconds:F1}s";
}
