using System;
using System.Diagnostics;
using System.Threading;

namespace TqkLibrary.WinDivert.SecureDns.Helpers;

/// <summary>
/// Lets one event through per interval and counts the ones it held back, so a line that could be
/// logged once per DNS query is logged once per interval with the number it stands for.
/// </summary>
/// <remarks>Thread-safe and lock-free; the caller keeps one instance per thing it throttles.</remarks>
public sealed class LogThrottle
{
    private readonly long _intervalTicks;
    private long _lastTicks;
    private int _suppressed;

    private readonly Func<long> _timestamp;

    public LogThrottle(TimeSpan interval) : this(interval, Stopwatch.GetTimestamp)
    {
    }

    /// <param name="timestamp">Clock in <see cref="Stopwatch.Frequency"/> ticks; tests pass a fake one.</param>
    public LogThrottle(TimeSpan interval, Func<long> timestamp)
    {
        _timestamp = timestamp ?? throw new ArgumentNullException(nameof(timestamp));
        _intervalTicks = (long)(interval.TotalSeconds * Stopwatch.Frequency);
    }

    /// <summary>
    /// True when the caller may log now; <paramref name="suppressed"/> is then how many calls since
    /// the last true answer were held back.
    /// </summary>
    public bool TryEnter(out int suppressed)
    {
        suppressed = 0;
        long now = _timestamp();
        long last = Volatile.Read(ref _lastTicks);
        if ((last != 0 && now - last < _intervalTicks)
            || Interlocked.CompareExchange(ref _lastTicks, now, last) != last)
        {
            Interlocked.Increment(ref _suppressed);
            return false;
        }
        suppressed = Interlocked.Exchange(ref _suppressed, 0);
        return true;
    }
}
