using System;
using System.Diagnostics;

namespace TqkLibrary.WinDivert.Pipeline.Helpers;

/// <summary>
/// How long packets sit in a pump: from the moment the driver captured one (its
/// <c>WINDIVERT_ADDRESS.Timestamp</c>) to the moment the pump hands it back.
/// </summary>
/// <remarks>
/// That span is the whole cost diversion adds to every packet of the machine — including the
/// packets of applications nothing redirects, which still make the round trip through user mode.
/// On a busy machine it is mostly the pump thread waiting for a core, and this is the number that
/// says whether it does.
/// <para>
/// The timestamp is a QueryPerformanceCounter value, the same clock as
/// <see cref="Stopwatch.GetTimestamp"/>, so no conversion is needed between the two.
/// </para>
/// <para>
/// Not thread-safe: owned by the one pump thread that records into it. Buckets are powers of two
/// in microseconds, so the percentiles are upper bounds within a factor of two — enough to tell
/// 50µs from 5ms, which is the question.
/// </para>
/// </remarks>
public sealed class PumpLatencyStats
{
    // Bucket i holds latencies in [2^(i-1), 2^i) µs; bucket 0 holds < 1µs. 2^26µs is ~67s.
    private const int BucketCount = 27;

    private readonly long[] _buckets = new long[BucketCount];
    private readonly long _reportIntervalTicks;
    private long _windowStart;
    private long _count;
    private long _sumMicros;
    private long _maxMicros;

    public PumpLatencyStats(TimeSpan reportInterval, long now)
    {
        _reportIntervalTicks = (long)(reportInterval.TotalSeconds * Stopwatch.Frequency);
        _windowStart = now;
    }

    /// <summary>Records one packet captured at <paramref name="captured"/> and released at <paramref name="now"/>.</summary>
    public void Record(long captured, long now)
    {
        // A zero timestamp (a test handle, an injected packet) or a clock that went backwards
        // across cores says nothing about the pump; skip it rather than skew the window.
        if (captured <= 0 || now < captured) return;
        long micros = (now - captured) * 1_000_000 / Stopwatch.Frequency;
        _buckets[BucketOf(micros)]++;
        _count++;
        _sumMicros += micros;
        if (micros > _maxMicros) _maxMicros = micros;
    }

    /// <summary>
    /// When the report interval has elapsed, returns the window's summary and starts a new one;
    /// null otherwise, and when the window saw no packets.
    /// </summary>
    public PumpLatencySummary? TryTakeSummary(long now)
    {
        if (now - _windowStart < _reportIntervalTicks) return null;
        PumpLatencySummary? summary = _count == 0
            ? null
            : new PumpLatencySummary(
                _count,
                _sumMicros / _count,
                UpperBoundOfPercentile(0.50),
                UpperBoundOfPercentile(0.99),
                _maxMicros,
                TimeSpan.FromSeconds((double)(now - _windowStart) / Stopwatch.Frequency));
        Array.Clear(_buckets);
        _count = 0;
        _sumMicros = 0;
        _maxMicros = 0;
        _windowStart = now;
        return summary;
    }

    private static int BucketOf(long micros)
    {
        if (micros <= 0) return 0;
        int bucket = 64 - System.Numerics.BitOperations.LeadingZeroCount((ulong)micros);
        return Math.Min(bucket, BucketCount - 1);
    }

    private long UpperBoundOfPercentile(double fraction)
    {
        long target = (long)Math.Ceiling(_count * fraction);
        long seen = 0;
        for (int i = 0; i < BucketCount; i++)
        {
            seen += _buckets[i];
            if (seen >= target) return Math.Min(1L << i, _maxMicros);
        }
        return _maxMicros;
    }
}

/// <summary>One report window of <see cref="PumpLatencyStats"/>; times in microseconds.</summary>
public readonly record struct PumpLatencySummary(
    long Count, long AverageMicros, long P50Micros, long P99Micros, long MaxMicros, TimeSpan Window);
