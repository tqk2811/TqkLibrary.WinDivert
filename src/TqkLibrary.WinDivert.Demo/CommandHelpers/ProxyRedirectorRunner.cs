using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.Proxy.Interfaces;
using TqkLibrary.WinDivert.Redirect;
using SysProcess = System.Diagnostics.Process;

namespace TqkLibrary.WinDivert.Demo.CommandHelpers;

internal static class ProxyRedirectorRunner
{
    public static async Task<int> RunAsync(
        uint pid,
        IProxySource proxySource,
        string proxyDisplay,
        bool exitWhenProcessGone,
        SuspendedProcessLauncher.SuspendedProcess? resumeBeforeRun,
        CancellationToken ct)
    {
        string logPath = Environment.GetEnvironmentVariable("WINDIVERT_LOG")
            ?? Path.Combine(Environment.CurrentDirectory, "windivert-interceptor.log");
        Console.WriteLine($"Diagnostic log: {logPath}");
        Console.WriteLine($"Upstream proxy : {proxyDisplay}");

        var opts = new RedirectOptions
        {
            ProcessId = pid,
            Protocols = RedirectProtocol.Tcp,
            LogFilePath = logPath,
            TcpConnectionHandler = (conn, innerCt) => HandleTcpAsync(conn, proxySource, innerCt),
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

        if (resumeBeforeRun != null)
        {
            try
            {
                resumeBeforeRun.Resume();
                Console.WriteLine($"Resumed pid={pid}");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Failed to resume process: " + ex.Message);
                return 1;
            }
        }

        Console.WriteLine();
        Console.WriteLine($"Redirecting pid={pid} TCP -> {proxyDisplay}. Relay port={redirector.TcpRelayPort}.");
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

    private static async Task HandleTcpAsync(RedirectedTcpConnection conn, IProxySource proxySource, CancellationToken ct)
    {
        Console.WriteLine($"  [TCP open ] pid={conn.ProcessId} {conn.OriginalSource} -> {conn.OriginalDestination} (via proxy)");
        IConnectSource? tunnel = null;
        try
        {
            tunnel = await proxySource.GetConnectSourceAsync(Guid.NewGuid(), ct).ConfigureAwait(false);

            var dst = conn.OriginalDestination;
            var target = new UriBuilder("tcp", dst.Address.ToString(), dst.Port).Uri;
            await tunnel.ConnectAsync(target, ct).ConfigureAwait(false);

            Stream proxyStream = await tunnel.GetStreamAsync(ct).ConfigureAwait(false);
            Stream clientStream = conn.ClientStream;

            Task c2p = CopyAsync(clientStream, proxyStream, ct);
            Task p2c = CopyAsync(proxyStream, clientStream, ct);
            await Task.WhenAny(c2p, p2c).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  [proxy err] {conn.OriginalDestination}: {ex.GetType().Name}: {ex.Message}");
        }
        finally
        {
            try { tunnel?.Dispose(); } catch { }
            Console.WriteLine($"  [TCP close] {conn.OriginalSource} -> {conn.OriginalDestination}");
        }
    }

    private static async Task CopyAsync(Stream from, Stream to, CancellationToken ct)
    {
        byte[] buf = new byte[16 * 1024];
        try
        {
            while (!ct.IsCancellationRequested)
            {
                int n = await from.ReadAsync(buf, 0, buf.Length, ct).ConfigureAwait(false);
                if (n <= 0) return;
                await to.WriteAsync(buf, 0, n, ct).ConfigureAwait(false);
                await to.FlushAsync(ct).ConfigureAwait(false);
            }
        }
        catch
        {
            // teardown observed by the caller via Task.WhenAny
        }
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
