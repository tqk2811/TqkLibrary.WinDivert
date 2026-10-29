using Microsoft.Extensions.Logging;

namespace TqkLibrary.WinDivert.Pipeline.Models;

/// <summary>
/// When a pump says, whatever the log level, that packets are sitting in it too long.
/// </summary>
/// <remarks>
/// The full latency report is Debug, which nobody runs day to day — and a slow pump is exactly the
/// thing worth knowing about on an ordinary day, because it slows every packet of the machine,
/// redirected or not. So the pump measures anyway and, once per report window, speaks up at
/// Information or Warning when the window's AVERAGE capture-to-release time crosses a threshold.
/// <para>
/// The average rather than the p99: the percentiles are power-of-two upper bounds, so a 1000µs
/// threshold compared against one would fire for anything over 512µs. The average is exact, and
/// the line still carries the p99 and the max.
/// </para>
/// <para>Microseconds, the unit the report is in. Zero or less turns that level off.</para>
/// </remarks>
public sealed class PumpLatencyAlertOptions
{
    public long InformationThresholdMicroseconds { get; set; } = 1_000;

    public long WarningThresholdMicroseconds { get; set; } = 10_000;

    /// <summary>Whether any level is on, i.e. whether the pump has to measure at all.</summary>
    /// <remarks>A method so a serializer writing these options to a file does not write it too.</remarks>
    public bool IsEnabled() => InformationThresholdMicroseconds > 0 || WarningThresholdMicroseconds > 0;

    /// <summary>The level a window averaging <paramref name="averageMicros"/> is reported at; <see cref="LogLevel.None"/> when it is not.</summary>
    public LogLevel LevelFor(long averageMicros)
    {
        if (WarningThresholdMicroseconds > 0 && averageMicros >= WarningThresholdMicroseconds) return LogLevel.Warning;
        if (InformationThresholdMicroseconds > 0 && averageMicros >= InformationThresholdMicroseconds) return LogLevel.Information;
        return LogLevel.None;
    }
}
