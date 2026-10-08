using Microsoft.Extensions.Logging;
using TqkLibrary.WinDivert.Native.Enums;
using TqkLibrary.WinDivert.Native.Interfaces;
using TqkLibrary.WinDivert.Native.Models;
using TqkLibrary.WinDivert.Packet;
using TqkLibrary.WinDivert.Pipeline;
using TqkLibrary.WinDivert.Pipeline.Models;
using Xunit;

namespace TqkLibrary.WinDivert.Tests;

/// <summary>
/// A pump whose loop throws outside the guarded pipeline must say so: a log line and a Stopped
/// event, not a faulted Task nobody observes.
/// </summary>
public sealed class PacketPumpCrashTests
{
    [Fact]
    public void AThrowingSendIsLoggedAndReportedAsAStop()
    {
        var handle = new ThrowingSendHandle();
        var logger = new CapturingLogger();
        var pump = new PacketPump("test", handle, _ => Task.CompletedTask, PacketParser.Default, logger);
        PumpStop? stop = null;
        using var stopped = new ManualResetEventSlim();
        pump.Stopped += s => { stop = s; stopped.Set(); };

        pump.Start();

        Assert.True(stopped.Wait(TimeSpan.FromSeconds(10)), "the crash was never reported");
        pump.Dispose();
        Assert.NotEqual(0, stop!.Value.Win32Error);
        Assert.Contains(logger.Entries, e => e.Level == LogLevel.Error && e.Message.Contains("crashed"));
        Assert.True(handle.Disposed);
    }

    private sealed class CapturingLogger : ILogger<PacketPump>
    {
        private readonly object _gate = new();
        private readonly List<(LogLevel Level, string Message)> _entries = new();

        public List<(LogLevel Level, string Message)> Entries { get { lock (_gate) return _entries.ToList(); } }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (_gate) _entries.Add((logLevel, formatter(state, exception)));
        }
    }

    // Hands the pump a packet, then throws from the send — the step outside the pipeline's guard.
    private sealed class ThrowingSendHandle : IWinDivertHandle
    {
        private static readonly byte[] Packet = BuildIpv4Udp();

        public bool Disposed { get; private set; }
        public WinDivertLayer Layer => WinDivertLayer.Network;
        public string Filter => "true";

        public bool TryRecv(byte[] buffer, out int length, out WinDivertAddress addr, out int win32Error)
        {
            Packet.CopyTo(buffer, 0);
            length = Packet.Length;
            addr = default;
            win32Error = 0;
            return true;
        }

        public bool TrySend(byte[] buffer, int length, ref WinDivertAddress addr)
            => throw new ObjectDisposedException("handle");

        public void CalcChecksums(byte[] buffer, int length, ref WinDivertAddress addr, WinDivertChecksumFlags flags = WinDivertChecksumFlags.All) { }
        public void SetParam(WinDivertParam param, ulong value) { }
        public ulong GetParam(WinDivertParam param) => 0;
        public void Shutdown(WinDivertShutdown how = WinDivertShutdown.Both) { }
        public void Dispose() => Disposed = true;

        private static byte[] BuildIpv4Udp()
        {
            byte[] p = new byte[28];
            p[0] = 0x45;
            p[3] = 28;
            p[8] = 64;
            p[9] = 17;
            p[25] = 8;
            return p;
        }
    }
}
