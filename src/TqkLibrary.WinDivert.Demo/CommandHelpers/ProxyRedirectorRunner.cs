using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
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
        ILoggerFactory? loggerFactory,
        bool followChildren,
        ushort[]? redirectDestinationPorts,
        bool enableDnsLookup,
        bool secureDns,
        Uri? dohEndpoint,
        CancellationToken ct)
    {
        string logPath = Environment.GetEnvironmentVariable("WINDIVERT_LOG")
            ?? Path.Combine(Environment.CurrentDirectory, "windivert-interceptor.log");
        Console.WriteLine($"Diagnostic log: {logPath}");
        Console.WriteLine($"Upstream proxy : {proxyDisplay}");

        // TCP -> upstream proxy via IConnectSource (CONNECT or SOCKS5 CMD=1).
        // UDP -> upstream proxy via SOCKS5 UDP ASSOCIATE (proxySource.IsSupportUdp).
        //        When unsupported or ASSOCIATE fails, UDP datagrams are DROPPED — never sent
        //        direct — so the real client IP is not leaked to UDP destinations.
        using var exitCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; exitCts.Cancel(); };

        UdpProxyForwarder? udpForwarder = null;
        // Captured by handler lambdas below; assigned just after construction so the handlers can
        // call into the redirector (e.g. DnsLookup.Resolve) without a circular constructor dep.
        ProcessRedirector? redirectorRef = null;
        var opts = new RedirectOptions
        {
            ProcessId = pid,
            Protocols = RedirectProtocol.All,
            LogFilePath = logPath,
            TcpConnectionHandler = (conn, innerCt) => HandleTcpAsync(conn, proxySource, loggerFactory, redirectorRef, innerCt),
            UdpDatagramHandler = (dg, innerCt) => udpForwarder?.OnDatagram(dg, innerCt) ?? DropUdpDatagram(dg, redirectorRef, innerCt),
            RedirectDestinationPorts = redirectDestinationPorts,
            EnableDnsLookup = enableDnsLookup,
            // Serve the target's DNS over HTTPS so it survives a UDP-incapable proxy. DNS/53 is then
            // claimed before NAT and never reaches the relay; other UDP still hits the relay where,
            // for a non-UDP proxy, it is dropped (no leak).
            EnableSecureDns = secureDns,
            DohEndpoint = dohEndpoint ?? new Uri("https://1.1.1.1/dns-query"),
        };

        using var redirector = new ProcessRedirector(opts);
        redirectorRef = redirector;
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

        string udpMode;
        if (proxySource.IsSupportUdp)
        {
            try
            {
                udpForwarder = new UdpProxyForwarder(proxySource, redirector, exitCts.Token);
                await udpForwarder.InitAsync().ConfigureAwait(false);
                udpMode = $"via proxy (relay listener={redirector.UdpRelayPort}, upstream relay={udpForwarder.RelayEndPoint})";
            }
            catch (Exception ex)
            {
                Console.WriteLine($"UDP ASSOCIATE failed, BLOCKING UDP to avoid IP leak: {ex.GetType().Name}: {ex.Message}");
                udpForwarder?.Dispose();
                udpForwarder = null;
                udpMode = $"BLOCKED (relay={redirector.UdpRelayPort}) — proxy refused UDP ASSOCIATE";
            }
        }
        else
        {
            udpMode = $"BLOCKED (relay={redirector.UdpRelayPort}) — proxy does not advertise IsSupportUdp";
        }

        ProcessTreeMonitor? treeMonitor = null;
        if (followChildren)
        {
            treeMonitor = new ProcessTreeMonitor(pid);
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
                udpForwarder?.Dispose();
                treeMonitor?.Dispose();
                return 1;
            }
        }

        string portFilterDesc = redirectDestinationPorts == null || redirectDestinationPorts.Length == 0
            ? "ALL ports"
            : "dst ports {" + string.Join(",", redirectDestinationPorts) + "} (other ports go DIRECT, no proxy)";
        Console.WriteLine();
        Console.WriteLine($"Redirecting pid={pid}: TCP -> {proxyDisplay} (relay={redirector.TcpRelayPort}); UDP -> {udpMode}.");
        Console.WriteLine($"Port filter: {portFilterDesc}.");
        if (secureDns)
            Console.WriteLine($"DNS: served via DoH {dohEndpoint ?? new Uri("https://1.1.1.1/dns-query")} (UDP/53 intercepted; other UDP per above).");
        Console.WriteLine("IPv6 of target: BLOCKED (interceptor is IPv4-only; v6 traffic would otherwise leak direct).");
        if (followChildren) Console.WriteLine($"Child process capture: ENABLED (polling every 500ms).");
        Console.WriteLine("Press Ctrl+C to stop.");

        if (exitWhenProcessGone)
            _ = Task.Run(() => WatchProcessAsync(pid, exitCts));

        try { await Task.Delay(-1, exitCts.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) { }

        udpForwarder?.Dispose();
        treeMonitor?.Dispose();
        Console.WriteLine("Stopping...");
        return 0;
    }

    // Returning null tells UdpRelayServer to skip the upstream direct send — without this the
    // datagram would leak the real client IP. Used both when the proxy refuses UDP ASSOCIATE
    // and when the proxy doesn't advertise UDP support at all.
    private static byte[]? DropUdpDatagram(RedirectedUdpDatagram dg, ProcessRedirector? redirector, CancellationToken ct)
    {
        string dst = FormatEndpoint(dg.OriginalDestination, redirector);
        Console.WriteLine($"  [UDP DROP ] pid={dg.ProcessId} {dg.OriginalSource} -> {dst} ({dg.Payload.Length} bytes)");
        return null;
    }

    private static string FormatEndpoint(System.Net.IPEndPoint ep, ProcessRedirector? redirector)
    {
        string? name = redirector?.DnsLookup?.Resolve(ep.Address);
        return name != null ? $"{ep} [{name}]" : ep.ToString();
    }

    private static async Task HandleTcpAsync(RedirectedTcpConnection conn, IProxySource proxySource, ILoggerFactory? loggerFactory, ProcessRedirector? redirector, CancellationToken ct)
    {
        Guid tunnelId = Guid.NewGuid();
        string dstLabel = FormatEndpoint(conn.OriginalDestination, redirector);
        Console.WriteLine($"  [TCP open ] {tunnelId:N} pid={conn.ProcessId} {conn.OriginalSource} -> {dstLabel} (via proxy)");
        IConnectSource? tunnel = null;
        try
        {
            tunnel = await proxySource.GetConnectSourceAsync(tunnelId, ct).ConfigureAwait(false);

            var dst = conn.OriginalDestination;
            var target = new UriBuilder("tcp", dst.Address.ToString(), dst.Port).Uri;
            await tunnel.ConnectAsync(target, ct).ConfigureAwait(false);

            // ForwardAsync wraps GetStreamAsync + StreamTransferHelper.WaitUntilDisconnect so the
            // chunk-by-chunk log lines ("[client -> proxy] N bytes") flow through the same
            // PXY/I/StreamTransferHelper bridge used by TqkLibrary.Proxy's own ProxyServer.
            await tunnel.ForwardAsync(conn.ClientStream, tunnelId, loggerFactory, cancellationToken: ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  [proxy err] {tunnelId:N} {dstLabel}: {ex.GetType().Name}: {ex.Message}");
            loggerFactory?.CreateLogger("TcpRelay")?.LogError(ex, "tunnel setup failed {TunnelId} -> {Target}", tunnelId, conn.OriginalDestination);
        }
        finally
        {
            try { tunnel?.Dispose(); } catch { }
            Console.WriteLine($"  [TCP close] {tunnelId:N} {conn.OriginalSource} -> {dstLabel}");
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
