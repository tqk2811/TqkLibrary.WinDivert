using System;
using Microsoft.Extensions.Logging;
using TqkLibrary.WinDivert.Redirect;

namespace TqkLibrary.WinDivert.Demo.Logging;

// Routes TqkLibrary.Proxy's ILogger output to two sinks:
//   * DiagnosticLogger (full detail, written to the windivert-interceptor.log file)
//   * Console for Warning and above, so connection failures surface in the live demo output
//
// TqkLibrary.Proxy reads Singleton.LoggerFactory once at the construction of any BaseLogger
// derived type (ProxySource / Tunnel / Server), so this must be installed BEFORE the first
// proxySource.GetConnectSourceAsync / GetUdpAssociateSourceAsync call.
internal sealed class ProxyLoggerBridge : ILoggerFactory
{
    private readonly LogLevel _minConsoleLevel;

    public ProxyLoggerBridge(LogLevel minConsoleLevel = LogLevel.Warning)
    {
        _minConsoleLevel = minConsoleLevel;
    }

    public ILogger CreateLogger(string categoryName) => new BridgeLogger(ShortName(categoryName), _minConsoleLevel);

    public void AddProvider(ILoggerProvider provider) { }
    public void Dispose() { }

    private static string ShortName(string fullName)
    {
        int idx = fullName.LastIndexOf('.');
        return idx >= 0 ? fullName.Substring(idx + 1) : fullName;
    }

    private sealed class BridgeLogger : ILogger
    {
        private readonly string _category;
        private readonly LogLevel _minConsoleLevel;

        public BridgeLogger(string category, LogLevel minConsoleLevel)
        {
            _category = category;
            _minConsoleLevel = minConsoleLevel;
        }

        public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

        public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel)) return;
            string body = formatter != null ? formatter(state, exception) : state?.ToString() ?? "";
            if (exception != null) body += $" | {exception.GetType().Name}: {exception.Message}";

            // Replace newlines so multi-line proxy traces stay in one log line.
            string flat = body.Replace("\r\n", " \\n ").Replace("\n", " \\n ");
            DiagnosticLogger.Log($"PXY/{LevelChar(logLevel)}/{_category}", flat);

            if (logLevel >= _minConsoleLevel)
                Console.WriteLine($"  [proxy {LevelText(logLevel)}] {_category}: {body}");
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
            _ => l.ToString().ToLowerInvariant(),
        };
    }

    private sealed class NullScope : IDisposable
    {
        public static readonly NullScope Instance = new NullScope();
        public void Dispose() { }
    }
}
