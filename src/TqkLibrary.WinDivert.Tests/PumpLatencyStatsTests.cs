using System;
using System.Diagnostics;
using TqkLibrary.WinDivert.Pipeline.Helpers;
using Xunit;

namespace TqkLibrary.WinDivert.Tests;

public class PumpLatencyStatsTests
{
    private static long Micros(long us) => us * Stopwatch.Frequency / 1_000_000;

    [Fact]
    public void NothingIsReportedBeforeTheIntervalHasElapsed()
    {
        var stats = new PumpLatencyStats(TimeSpan.FromSeconds(10), now: 1000);
        stats.Record(1000, 1000 + Micros(100));

        Assert.Null(stats.TryTakeSummary(1000 + Micros(5_000_000)));
    }

    [Fact]
    public void AWindowReportsCountAverageMaxAndPercentileBounds()
    {
        long start = 1000;
        var stats = new PumpLatencyStats(TimeSpan.FromSeconds(1), start);
        for (int i = 0; i < 99; i++) stats.Record(start, start + Micros(50));
        stats.Record(start, start + Micros(20_000));

        PumpLatencySummary? s = stats.TryTakeSummary(start + Micros(1_000_000));

        Assert.NotNull(s);
        Assert.Equal(100, s.Value.Count);
        Assert.Equal(20_000, s.Value.MaxMicros);
        Assert.Equal((99 * 50 + 20_000) / 100, s.Value.AverageMicros);
        Assert.Equal(64, s.Value.P50Micros);   // 50us falls in the [32, 64) bucket
        Assert.Equal(64, s.Value.P99Micros);
    }

    [Fact]
    public void TakingASummaryStartsAFreshWindow()
    {
        long start = 1000;
        var stats = new PumpLatencyStats(TimeSpan.FromSeconds(1), start);
        stats.Record(start, start + Micros(50));
        long next = start + Micros(1_000_000);
        Assert.NotNull(stats.TryTakeSummary(next));

        Assert.Null(stats.TryTakeSummary(next + Micros(1_000_000)));  // empty window
    }

    [Fact]
    public void MissingOrBackwardTimestampsAreIgnored()
    {
        long start = 1000;
        var stats = new PumpLatencyStats(TimeSpan.FromSeconds(1), start);
        stats.Record(0, start);
        stats.Record(start + 10, start);

        Assert.Null(stats.TryTakeSummary(start + Micros(1_000_000)));
    }
}
