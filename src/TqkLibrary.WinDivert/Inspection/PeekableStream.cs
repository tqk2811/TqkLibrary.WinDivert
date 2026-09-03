using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace TqkLibrary.WinDivert.Inspection;

// Stream decorator that lets a caller look at the first bytes of a connection and then hand the
// stream on as if nothing had been read. Reading the TLS ClientHello (for SNI) or the HTTP
// request line (for Host) is exactly this: the bytes must still reach the upstream verbatim.
//
// Ownership: the inner stream is NOT disposed by this wrapper.
public sealed class PeekableStream : Stream
{
    private readonly Stream _inner;
    private byte[] _peeked = Array.Empty<byte>();
    private int _peekedLength;
    private int _peekedConsumed;

    public PeekableStream(Stream inner)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    }

    // Bytes already read from the socket and not yet handed to a reader.
    public int BufferedCount => _peekedLength - _peekedConsumed;

    // Performs ONE read into the peek buffer (unless it already holds maxTotal bytes) and returns
    // how many bytes are buffered afterwards, WITHOUT consuming them. The returned count is what a
    // parser may read from PeekBuffer starting at index 0.
    //
    // One read, not "read until full", on purpose: the caller cannot know how many bytes the first
    // flight will be. A TLS ClientHello is ~500 bytes, so waiting for a 2 KB buffer to fill would
    // block until the peer sends something else — which for a request/response protocol never
    // happens, and the peek would time out with the name sitting unparsed in the buffer.
    // Callers loop: parse what is here, ask for more only if the message is still incomplete.
    public async Task<int> PeekAsync(int maxTotal, CancellationToken ct)
    {
        if (maxTotal <= 0) return BufferedCount;
        // Peeking twice in a row should extend the window, not restart it, so compaction happens
        // only when a reader has already consumed part of the buffer.
        Compact();
        if (_peekedLength >= maxTotal) return _peekedLength;
        if (_peeked.Length < maxTotal) Array.Resize(ref _peeked, maxTotal);

        int read = await _inner.ReadAsync(_peeked, _peekedLength, maxTotal - _peekedLength, ct).ConfigureAwait(false);
        if (read > 0) _peekedLength += read;
        return _peekedLength;
    }

    // The buffer backing PeekAsync. Valid up to the length that PeekAsync returned.
    public byte[] PeekBuffer => _peeked;

    private void Compact()
    {
        if (_peekedConsumed == 0) return;
        int remaining = _peekedLength - _peekedConsumed;
        if (remaining > 0) Buffer.BlockCopy(_peeked, _peekedConsumed, _peeked, 0, remaining);
        _peekedLength = remaining;
        _peekedConsumed = 0;
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
        int fromBuffer = TakeBuffered(buffer, offset, count);
        return fromBuffer > 0 ? fromBuffer : _inner.Read(buffer, offset, count);
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        int fromBuffer = TakeBuffered(buffer, offset, count);
        // Never mix buffered bytes with a fresh socket read in one call: returning the short
        // buffered chunk first keeps ordering correct and costs one extra call at most.
        return fromBuffer > 0
            ? Task.FromResult(fromBuffer)
            : _inner.ReadAsync(buffer, offset, count, cancellationToken);
    }

    private int TakeBuffered(byte[] buffer, int offset, int count)
    {
        int available = _peekedLength - _peekedConsumed;
        if (available <= 0) return 0;
        int n = Math.Min(available, count);
        Buffer.BlockCopy(_peeked, _peekedConsumed, buffer, offset, n);
        _peekedConsumed += n;
        if (_peekedConsumed == _peekedLength)
        {
            _peekedConsumed = 0;
            _peekedLength = 0;
        }
        return n;
    }

    public override void Write(byte[] buffer, int offset, int count) => _inner.Write(buffer, offset, count);

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => _inner.WriteAsync(buffer, offset, count, cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();
}
