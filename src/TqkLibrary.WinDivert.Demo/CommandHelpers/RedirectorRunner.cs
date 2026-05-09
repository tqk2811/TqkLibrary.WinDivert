using System;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.WinDivert.Redirect;
using SysProcess = System.Diagnostics.Process;

namespace TqkLibrary.WinDivert.Demo.CommandHelpers;

internal static class RedirectorRunner
{
    public static async Task<int> RunAsync(
        uint pid,
        RedirectProtocol proto,
        bool exitWhenProcessGone,
        SuspendedProcessLauncher.SuspendedProcess? suspended,
        CancellationToken ct)
    {
        string logPath = Environment.GetEnvironmentVariable("WINDIVERT_LOG")
            ?? System.IO.Path.Combine(Environment.CurrentDirectory, "windivert-interceptor.log");
        Console.WriteLine($"Diagnostic log: {logPath}");

        var opts = new RedirectOptions
        {
            ProcessId = pid,
            Protocols = proto,
            LogFilePath = logPath,
            TcpConnectionHandler = async (conn, innerCt) =>
            {
                Console.WriteLine($"  [TCP open ] pid={conn.ProcessId} {conn.OriginalSource} -> {conn.OriginalDestination}");
                try
                {
                    await conn.RelayAsync(innerCt).ConfigureAwait(false);
                }
                finally
                {
                    Console.WriteLine($"  [TCP close] {conn.OriginalSource} -> {conn.OriginalDestination}");
                }
            },
            UdpDatagramHandler = (dg, _) =>
            {
                Console.WriteLine($"  [UDP dgram] pid={dg.ProcessId} {dg.OriginalSource} -> {dg.OriginalDestination} ({dg.Payload.Length} bytes)");
                return dg.Payload; // pass through
            },
        };

        using var redirector = new ProcessRedirector(opts);
        redirector.TcpConnectEstablished += k => Console.WriteLine($"  [track +  ] {k}");
        redirector.TcpConnectClosed += k => Console.WriteLine($"  [track -  ] {k}");

        try
        {
            redirector.Start();
        }
        catch (Exception ex)
        {
            Console.WriteLine("Failed to start redirector: " + ex.Message);
            Console.WriteLine("Check: running as Admin, WinDivert driver installed.");
            return 1;
        }

        if (suspended != null)
        {
            try
            {
                suspended.Resume();
                Console.WriteLine($"Resumed pid={pid}");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Failed to resume process: " + ex.Message);
                return 1;
            }
        }

        Console.WriteLine();
        Console.WriteLine($"Redirecting pid={pid}. TCP relay port={redirector.TcpRelayPort}, UDP relay port={redirector.UdpRelayPort}.");
        Console.WriteLine("Press Ctrl+C to stop.");

        using var exitCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; exitCts.Cancel(); };

        if (exitWhenProcessGone)
            _ = Task.Run(() => WatchProcessAsync(pid, exitCts));

        try { await Task.Delay(-1, exitCts.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) { }

        Console.WriteLine("Stopping...");
        return 0;
    }

    private static async Task WatchProcessAsync(uint pid, CancellationTokenSource exitCts)
    {
        while (!exitCts.IsCancellationRequested)
        {
            try
            {
                using var p = SysProcess.GetProcessById((int)pid);
                if (p.HasExited) break;
            }
            catch { break; }
            try { await Task.Delay(500, exitCts.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
        }
        Console.WriteLine($"Target process {pid} exited; stopping.");
        exitCts.Cancel();
    }
}
