using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace TqkLibrary.WinDivert.Redirect;

// Stream decorator that tallies traffic into a ConnectionStatistics. Reads count as "from the
// process", writes as "to the process" — the wrapper always sits on the CLIENT side of a
// redirected connection, so the direction naming holds regardless of what the caller pipes it to.
//
// Ownership: the inner stream is NOT disposed by this wrapper (the owning TcpClient closes it).
public sealed class CountingStream : Stream
{
    private readonly Stream _inner;
    private readonly ConnectionStatistics _statistics;

    public CountingStream(Stream inner, ConnectionStatistics statistics)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _statistics = statistics ?? throw new ArgumentNullException(nameof(statistics));
    }

    public override bool CanRead => _inner.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => _inner.CanWrite;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush() => _inner.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

    public override int Read(byte[] buffer, int offset, int count)
    {
        int read = _inner.Read(buffer, offset, count);
        if (read > 0) _statistics.AddFromProcess(read);
        return read;
    }

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        int read = await _inner.ReadAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
        if (read > 0) _statistics.AddFromProcess(read);
        return read;
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        _inner.Write(buffer, offset, count);
        if (count > 0) _statistics.AddToProcess(count);
    }

    public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        await _inner.WriteAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
        if (count > 0) _statistics.AddToProcess(count);
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();
}
