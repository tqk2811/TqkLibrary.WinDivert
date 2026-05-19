using System;
using System.IO;

namespace TqkLibrary.WinDivert.Redirect;

// File-based diagnostic logger shared by PacketInterceptor and SocketTracker.
// Single global writer protected by a lock; AutoFlush so a crash still leaves a complete tail.
// Public so external bridges (e.g. demo's proxy ILogger adapter) can write to the same file.
public static class DiagnosticLogger
{
    private static readonly object _lock = new object();
    private static StreamWriter? _writer;

    public static bool Enabled
    {
        get { lock (_lock) return _writer != null; }
    }

    // Always truncates: each Configure call starts a fresh log so previous-session content
    // never bleeds into the new run. File.Delete first defeats editors that hold a read handle
    // and would otherwise let stale bytes leak past FileMode.Create's truncation.
    public static void Configure(string? path)
    {
        lock (_lock)
        {
            _writer?.Flush();
            _writer?.Dispose();
            _writer = null;
            if (string.IsNullOrEmpty(path)) return;
            string? dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            try { if (File.Exists(path!)) File.Delete(path!); } catch { /* in-use; FileMode.Create will still truncate */ }
            var fs = new FileStream(path!, FileMode.Create, FileAccess.Write, FileShare.Read);
            _writer = new StreamWriter(fs) { AutoFlush = true };
            _writer.WriteLine($"=== windivert log opened {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss.fff} UTC (cleared) ===");
        }
    }

    public static void Log(string tag, string message)
    {
        lock (_lock)
        {
            if (_writer == null) return;
            _writer.WriteLine($"{DateTime.UtcNow:HH:mm:ss.fff} [{tag}] {message}");
        }
    }

    public static void Close()
    {
        lock (_lock)
        {
            _writer?.Flush();
            _writer?.Dispose();
            _writer = null;
        }
    }
}
