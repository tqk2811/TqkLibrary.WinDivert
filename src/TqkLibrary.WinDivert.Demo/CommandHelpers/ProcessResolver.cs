using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.WinDivert.Process;
using SysProcess = System.Diagnostics.Process;

namespace TqkLibrary.WinDivert.Demo.CommandHelpers;

internal static class ProcessResolver
{
    public static async Task<uint?> ResolveAsync(string? selector, bool wait, int timeoutSeconds, CancellationToken ct)
    {
        if (selector == null)
            return SelectInteractive();

        if (!wait)
        {
            uint? pid = TryResolve(selector);
            if (pid == null)
                Console.WriteLine($"Process '{selector}' not found.");
            return pid;
        }

        Console.WriteLine($"Waiting for process '{selector}' (timeout {timeoutSeconds}s)...");
        var deadline = DateTime.UtcNow.AddSeconds(timeoutSeconds);
        while (DateTime.UtcNow < deadline && !ct.IsCancellationRequested)
        {
            uint? pid = TryResolve(selector);
            if (pid != null)
            {
                Console.WriteLine($"  found pid={pid.Value}");
                return pid;
            }
            try { await Task.Delay(250, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return null; }
        }
        Console.WriteLine($"Timeout waiting for '{selector}'.");
        return null;
    }

    private static uint? TryResolve(string selector)
    {
        if (uint.TryParse(selector, out uint pid))
        {
            try
            {
                using var p = SysProcess.GetProcessById((int)pid);
                return pid;
            }
            catch { return null; }
        }

        var matches = ProcessFinder.ListAll()
            .Where(p => p.Name.IndexOf(selector, StringComparison.OrdinalIgnoreCase) >= 0)
            .ToList();
        if (matches.Count == 0) return null;
        if (matches.Count > 1)
            Console.WriteLine($"  multiple matches for '{selector}', picking first: {matches[0]}");
        return matches[0].Id;
    }

    public static uint? SelectInteractive()
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

    private static void PrintProcesses(IEnumerable<ProcessInfo> ps)
    {
        Console.WriteLine("  PID      Name");
        Console.WriteLine("  -------- --------------------");
        foreach (var p in ps)
            Console.WriteLine($"  {p.Id,-8} {p.Name}");
    }
}
