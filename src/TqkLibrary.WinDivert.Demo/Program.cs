using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.WinDivert.Process;
using TqkLibrary.WinDivert.Redirect;

namespace TqkLibrary.WinDivert.Demo;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        Console.Title = "TqkLibrary.WinDivert Demo";
        Console.WriteLine("== TqkLibrary.WinDivert Demo ==");
        Console.WriteLine("(requires Administrator + WinDivert.dll/WinDivert64.sys next to exe)");
        Console.WriteLine();

        uint? pid = SelectProcess();
        if (pid == null) return 0;

        RedirectProtocol proto = SelectProtocols();
        if (proto == RedirectProtocol.None) return 0;

        var opts = new RedirectOptions
        {
            ProcessId = pid.Value,
            Protocols = proto,
            TcpConnectionHandler = async (conn, ct) =>
            {
                Console.WriteLine($"  [TCP open ] pid={conn.ProcessId} {conn.OriginalSource} -> {conn.OriginalDestination}");
                try
                {
                    await conn.RelayAsync(ct).ConfigureAwait(false);
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

        Console.WriteLine();
        Console.WriteLine($"Redirecting pid={pid.Value}. TCP relay port={redirector.TcpRelayPort}, UDP relay port={redirector.UdpRelayPort}.");
        Console.WriteLine("Press Ctrl+C to stop.");

        var exitCts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; exitCts.Cancel(); };
        try { await Task.Delay(-1, exitCts.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) { }

        Console.WriteLine("Stopping...");
        return 0;
    }

    private static uint? SelectProcess()
    {
        while (true)
        {
            Console.Write("Enter PID, process name (substring), or 'list': ");
            string? input = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(input)) return null;
            input = input.Trim();

            if (uint.TryParse(input, out uint pid))
                return pid;

            if (input.Equals("list", StringComparison.OrdinalIgnoreCase))
            {
                PrintProcesses(ProcessFinder.ListAll().Take(200));
                continue;
            }

            var matches = ProcessFinder.ListAll()
                .Where(p => p.Name.IndexOf(input, StringComparison.OrdinalIgnoreCase) >= 0)
                .ToList();
            if (matches.Count == 0)
            {
                Console.WriteLine("  (no matches)");
                continue;
            }
            if (matches.Count == 1)
            {
                Console.WriteLine($"  picked: {matches[0]}");
                return matches[0].Id;
            }
            PrintProcesses(matches);
        }
    }

    private static void PrintProcesses(System.Collections.Generic.IEnumerable<ProcessInfo> ps)
    {
        Console.WriteLine("  PID      Name");
        Console.WriteLine("  -------- --------------------");
        foreach (var p in ps)
            Console.WriteLine($"  {p.Id,-8} {p.Name}");
    }

    private static RedirectProtocol SelectProtocols()
    {
        Console.Write("Protocols [T=TCP, U=UDP, B=both] (default T): ");
        string? s = Console.ReadLine();
        if (string.IsNullOrWhiteSpace(s)) return RedirectProtocol.Tcp;
        s = s.Trim().ToLowerInvariant();
        return s switch
        {
            "u" => RedirectProtocol.Udp,
            "b" => RedirectProtocol.All,
            "t" => RedirectProtocol.Tcp,
            _ => RedirectProtocol.Tcp,
        };
    }
}
