using TqkLibrary.WinDivert.SecureDns.Helpers;
using Xunit;

namespace TqkLibrary.WinDivert.Tests;

public class LogThrottleTests
{
    private sealed class FakeClock
    {
        // Never 0: the throttle reads 0 as "nothing let through yet".
        public long Ticks { get; set; } = 1000;

        public void Advance(TimeSpan span) => Ticks += (long)(span.TotalSeconds * System.Diagnostics.Stopwatch.Frequency);
    }

    [Fact]
    public void First_call_enters_with_nothing_held_back()
    {
        var throttle = new LogThrottle(TimeSpan.FromSeconds(30), () => 1000L);

        Assert.True(throttle.TryEnter(out int suppressed));
        Assert.Equal(0, suppressed);
    }

    [Fact]
    public void Calls_within_the_interval_are_held_back_and_counted()
    {
        var clock = new FakeClock();
        var throttle = new LogThrottle(TimeSpan.FromSeconds(30), () => clock.Ticks);
        Assert.True(throttle.TryEnter(out _));

        clock.Advance(TimeSpan.FromSeconds(5));
        Assert.False(throttle.TryEnter(out int s1));
        clock.Advance(TimeSpan.FromSeconds(24));
        Assert.False(throttle.TryEnter(out int s2));

        Assert.Equal(0, s1);
        Assert.Equal(0, s2);
    }

    [Fact]
    public void Call_after_the_interval_enters_and_reports_the_count()
    {
        var clock = new FakeClock();
        var throttle = new LogThrottle(TimeSpan.FromSeconds(30), () => clock.Ticks);
        Assert.True(throttle.TryEnter(out _));
        clock.Advance(TimeSpan.FromSeconds(1));
        throttle.TryEnter(out _);
        throttle.TryEnter(out _);
        throttle.TryEnter(out _);

        clock.Advance(TimeSpan.FromSeconds(30));
        Assert.True(throttle.TryEnter(out int suppressed));
        Assert.Equal(3, suppressed);

        // The count starts over, and the interval restarts from that entry.
        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.False(throttle.TryEnter(out _));
        clock.Advance(TimeSpan.FromSeconds(20));
        Assert.True(throttle.TryEnter(out int next));
        Assert.Equal(1, next);
    }
}
