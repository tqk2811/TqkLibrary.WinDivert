using System;
using System.IO;
using Microsoft.Extensions.Logging;

namespace TqkLibrary.WinDivert.Demo.Logging;

/// <summary>
/// Where this demo's log lines go: a file with everything, and the console with the few lines a
/// person watching the run needs.
/// </summary>
/// <remarks>
/// The library deliberately ships no sink of its own — it logs through <c>ILogger&lt;T&gt;</c> and
/// leaves the destination to the host. This provider is that decision, made once, for this app;
/// a GUI host would write one that raises an event per line and bind a log pane to it instead.
/// </remarks>
internal sealed class DemoLoggerProvider : ILoggerProvider
{
    private readonly object _lock = new object();
    private readonly LogLevel _minConsoleLevel;
    private StreamWriter? _writer;

    public DemoLoggerProvider(string? filePath, LogLevel minConsoleLevel = LogLevel.Information)
    {
        _minConsoleLevel = minConsoleLevel;
        if (!string.IsNullOrEmpty(filePath)) OpenFile(filePath!);
    }

    public ILogger CreateLogger(string categoryName) => new DemoLogger(this, ShortName(categoryName));

    private void OpenFile(string path)
    {
        try
        {
            string? dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir!);
            // Delete first: an editor holding a read handle would otherwise let stale bytes
            // survive past the truncation FileMode.Create is supposed to do.
            try { if (File.Exists(path)) File.Delete(path); } catch { }
            var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read);
            _writer = new StreamWriter(fs) { AutoFlush = true };
            _writer.WriteLine($"=== windivert demo log opened {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss.fff} UTC ===");
        }
        catch (Exception ex)
        {
            // A log file we cannot open must not take the run down with it.
            _writer = null;
            Console.WriteLine($"  [log] cannot write {path}: {ex.Message}");
        }
    }

    private void Write(LogLevel level, string category, string message)
    {
        lock (_lock)
        {
            _writer?.WriteLine($"{DateTime.UtcNow:HH:mm:ss.fff} [{LevelChar(level)}] {category}: {message}");
        }

        if (level >= _minConsoleLevel)
            Console.WriteLine($"  [{LevelText(level)}] {category}: {message}");
    }

    private static string ShortName(string fullName)
    {
        int idx = fullName.LastIndexOf('.');
        return idx >= 0 ? fullName.Substring(idx + 1) : fullName;
    }

    private static char LevelChar(LogLevel l) => l switch
    {
        LogLevel.Trace => 'T',
        LogLevel.Debug => 'D',
        LogLevel.Information => 'I',
        LogLevel.Warning => 'W',
        LogLevel.Error => 'E',
        LogLevel.Critical => 'C',
        _ => '?',
    };

    private static string LevelText(LogLevel l) => l switch
    {
        LogLevel.Warning => "warn",
        LogLevel.Error => "err ",
        LogLevel.Critical => "crit",
        _ => "info",
    };

    public void Dispose()
    {
        lock (_lock)
        {
            try { _writer?.Flush(); } catch { }
            try { _writer?.Dispose(); } catch { }
            _writer = null;
        }
    }

    private sealed class DemoLogger : ILogger
    {
        private readonly DemoLoggerProvider _provider;
        private readonly string _category;

        public DemoLogger(DemoLoggerProvider provider, string category)
        {
            _provider = provider;
            _category = category;
        }

        public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

        public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel)) return;
            string body = formatter != null ? formatter(state, exception) : state?.ToString() ?? "";
            if (exception != null) body += $" | {exception.GetType().Name}: {exception.Message}";

            // Flatten, so a multi-line trace stays one log line and the file stays greppable.
            _provider.Write(logLevel, _category, body.Replace("\r\n", " \\n ").Replace("\n", " \\n "));
        }

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new NullScope();
            public void Dispose() { }
        }
    }
}
