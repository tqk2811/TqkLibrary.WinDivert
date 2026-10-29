using Microsoft.Extensions.Logging;
using TqkLibrary.WinDivert.Pipeline.Models;
using Xunit;

namespace TqkLibrary.WinDivert.Tests;

public class PumpLatencyAlertOptionsTests
{
    [Theory]
    [InlineData(0, LogLevel.None)]
    [InlineData(999, LogLevel.None)]
    [InlineData(1_000, LogLevel.Information)]
    [InlineData(9_999, LogLevel.Information)]
    [InlineData(10_000, LogLevel.Warning)]
    [InlineData(1_000_000, LogLevel.Warning)]
    public void TheDefaultsAreOneMillisecondForInformationAndTenForWarning(long averageMicros, LogLevel expected)
        => Assert.Equal(expected, new PumpLatencyAlertOptions().LevelFor(averageMicros));

    [Fact]
    public void AThresholdOfZeroTurnsThatLevelOff()
    {
        var options = new PumpLatencyAlertOptions { WarningThresholdMicroseconds = 0 };

        Assert.Equal(LogLevel.Information, options.LevelFor(50_000));
        Assert.True(options.IsEnabled());
    }

    [Fact]
    public void BothThresholdsOffMeansNothingToMeasure()
    {
        var options = new PumpLatencyAlertOptions { InformationThresholdMicroseconds = 0, WarningThresholdMicroseconds = -1 };

        Assert.Equal(LogLevel.None, options.LevelFor(50_000));
        Assert.False(options.IsEnabled());
    }
}
