using System;
using System.IO;
using Microsoft.Extensions.Logging;

namespace TqkLibrary.WinDivert.Logging;

// Diagnostic sink for one redirector. Replaces the old process-wide static logger: an instance is
// created by ProcessRedirector and handed to every component it owns, so two redirectors in the
// same process no longer fight over one file, and a host application can capture the stream
// without touching global state.
//
// Three outputs, all optional and independent:
//   * ILogger      — for a host that already has logging configured
//   * a file       — the historical behaviour, still the fastest way to debug a redirect session
//   * EntryWritten — live events for a UI log pane
//
// Ownership: the ILoggerFactory is NOT owned (the caller keeps it); the file handle is, and is
// closed on Dispose. Use RedirectLogger.Null for "log nothing" instead of a null reference.
public sealed class RedirectLogger : IDisposable
{
    private readonly object _lock = new object();
    private readonly ILogger? _logger;
    private StreamWriter? _writer;

    /// <summary>A logger that discards everything. Cheap: no file, no events.</summary>
    public static RedirectLogger Null { get; } = new RedirectLogger();

    /// <summary>Raised for every line. Subscribers run on the calling thread — keep them short.</summary>
    public event Action<RedirectLogEntry>? EntryWritten;

    /// <param name="loggerFactory">Host logging, or null.</param>
    /// <param name="filePath">Diagnostic file, or null. The file is truncated on open so a new
    /// session never reads as a continuation of the previous one.</param>
    public RedirectLogger(ILoggerFactory? loggerFactory = null, string? filePath = null)
    {
        _logger = loggerFactory?.CreateLogger("TqkLibrary.WinDivert");
        if (!string.IsNullOrEmpty(filePath)) OpenFile(filePath!);
    }

    // True when at least one output would receive the line. Callers can skip building expensive
    // messages when nothing is listening.
    public bool IsEnabled
    {
        get
        {
            if (_logger != null || EntryWritten != null) return true;
            lock (_lock) return _writer != null;
        }
    }

    public void Log(string tag, string message)
    {
        var entry = new RedirectLogEntry(DateTime.UtcNow, tag, message);

        lock (_lock)
        {
            _writer?.WriteLine(entry.ToString());
        }

        _logger?.LogDebug("[{Tag}] {Message}", tag, message);

        try { EntryWritten?.Invoke(entry); }
        catch { /* a broken subscriber must not break the packet path */ }
    }

    private void OpenFile(string path)
    {
        try
        {
            string? dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir!);
            // Delete first: an editor holding a read handle would otherwise let stale bytes
            // survive past FileMode.Create's truncation.
            try { if (File.Exists(path)) File.Delete(path); } catch { }
            var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read);
            _writer = new StreamWriter(fs) { AutoFlush = true };
            _writer.WriteLine($"=== windivert log opened {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss.fff} UTC ===");
        }
        catch (Exception ex)
        {
            // A logger that cannot open its file must not take the redirector down with it.
            _writer = null;
            _logger?.LogWarning(ex, "Cannot open diagnostic log file {Path}", path);
        }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            try { _writer?.Flush(); } catch { }
            try { _writer?.Dispose(); } catch { }
            _writer = null;
        }
    }
}
