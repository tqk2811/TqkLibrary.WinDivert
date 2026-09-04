using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using TqkLibrary.WinDivert.ProcessControl.Interfaces;
using TqkLibrary.WinDivert.Redirect;
using TqkLibrary.WinDivert.Redirect.Interfaces;
using SysProcess = System.Diagnostics.Process;

namespace TqkLibrary.WinDivert.Demo.Running;

// The simplest thing the library can do: capture a process and relay every connection straight to
// where it was already going. Nothing is rerouted — this exists to show that the capture itself
// works, and to print what it sees.
internal sealed class RedirectorRunner
{
    private readonly IProcessRedirectorFactory _redirectorFactory;
    private readonly IProcessTreeMonitorFactory _treeMonitorFactory;

    public RedirectorRunner(IServiceProvider services)
    {
        if (services is null) throw new ArgumentNullException(nameof(services));
        _redirectorFactory = services.GetRequiredService<IProcessRedirectorFactory>();
        _treeMonitorFactory = services.GetRequiredService<IProcessTreeMonitorFactory>();
    }

    public async Task<int> RunAsync(
        uint pid,
        RedirectProtocol proto,
        bool exitWhenProcessGone,
        ISuspendedProcess? suspended,
        bool followChildren,
        CancellationToken ct)
    {
        var opts = new RedirectOptions
        {
            ProcessId = pid,
            Protocols = proto,
            TcpConnectionHandler = async (conn, innerCt) =>
            {
                Console.WriteLine($"  [TCP open ] pid={conn.ProcessId} {conn.OriginalSource} -> {conn.OriginalDestination}");
                try
                {
                    await conn.RelayDirectAsync(innerCt).ConfigureAwait(false);
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

        using IProcessRedirector redirector = _redirectorFactory.Create(opts);
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

        IProcessTreeMonitor? treeMonitor = null;
        if (followChildren)
        {
            treeMonitor = _treeMonitorFactory.Create(pid);
            treeMonitor.ChildSpawned += (childPid, parentPid) =>
            {
                Console.WriteLine($"  [child +  ] pid={childPid} parent={parentPid} -> tracking");
                try { redirector.AddTrackedProcessId(childPid); }
                catch (Exception ex)
                {
                    Console.WriteLine($"  [child err] pid={childPid}: {ex.GetType().Name}: {ex.Message}");
                }
            };
            treeMonitor.Start();
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
                treeMonitor?.Dispose();
                return 1;
            }
        }

        Console.WriteLine();
        Console.WriteLine($"Redirecting pid={pid}. TCP relay port={redirector.TcpRelayPort}, UDP relay port={redirector.UdpRelayPort}.");
        if (followChildren) Console.WriteLine("Child process capture: ENABLED.");
        Console.WriteLine("Press Ctrl+C to stop.");

        using var exitCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; exitCts.Cancel(); };

        if (exitWhenProcessGone)
            _ = Task.Run(() => WatchProcessAsync(pid, exitCts));

        try { await Task.Delay(-1, exitCts.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) { }

        treeMonitor?.Dispose();
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
