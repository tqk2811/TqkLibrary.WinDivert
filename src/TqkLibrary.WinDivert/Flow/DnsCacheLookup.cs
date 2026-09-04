using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using SysProcess = System.Diagnostics.Process;

namespace TqkLibrary.WinDivert.Flow;

// Background reverse-resolver that maps IP -> domain(s) by periodically parsing the output of
// `ipconfig /displaydns`. The system DNS Client Service cache is the source of truth — entries
// appear when any process on the machine resolves a name via the standard Win32 resolver
// (including the target game) and stay until TTL expiry.
//
// This is best-effort:
//   - DoH/DoT clients bypass the system resolver and leave nothing in the cache.
//   - TTL expiry pushes entries out; we mitigate by accumulating (never remove) within process
//     lifetime, so a name once seen for an IP keeps resolving until the redirector restarts.
//   - Locale labels in ipconfig output (English / Japanese / Vietnamese / ...) differ; the
//     parser is structural and only depends on the universal ` : ` separator and the dashed
//     line that delimits each record block — so it is locale-independent.
public sealed class DnsCacheLookup : IDnsCacheLookup
{
    private readonly Dictionary<IPAddress, HashSet<string>> _map = new();
    private readonly object _lock = new();
    private readonly TimeSpan _interval;
    private readonly CancellationTokenSource _cts = new();
    private Task? _loopTask;

    public DnsCacheLookup(TimeSpan? refreshInterval = null)
    {
        _interval = refreshInterval ?? TimeSpan.FromSeconds(15);
    }

    public void Start()
    {
        if (_loopTask != null) return;
        _loopTask = Task.Run(() => RefreshLoopAsync(_cts.Token));
    }

    public string? Resolve(IPAddress? ip)
    {
        if (ip == null) return null;
        lock (_lock)
        {
            if (_map.TryGetValue(ip, out var set) && set.Count > 0)
                return string.Join(",", set);
        }
        return null;
    }

    private async Task RefreshLoopAsync(CancellationToken ct)
    {
        try { Refresh(); } catch { /* swallow */ }
        while (!ct.IsCancellationRequested)
        {
            try { await Task.Delay(_interval, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
            try { Refresh(); } catch { /* swallow */ }
        }
    }

    private void Refresh()
    {
        var psi = new ProcessStartInfo("ipconfig", "/displaydns")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        using var p = SysProcess.Start(psi);
        if (p == null) return;
        string output = p.StandardOutput.ReadToEnd();
        p.WaitForExit(10_000);
        Parse(output);
    }

    private void Parse(string output)
    {
        string? currentName = null;
        string[] lines = output.Split('\n');
        for (int i = 0; i < lines.Length; i++)
        {
            string line = lines[i].TrimEnd('\r');
            string trimmed = line.Trim();

            // Block delimiter line: "----------------------------------------" (≥ 10 dashes).
            // The line immediately above is the canonical record name for the following block.
            if (trimmed.Length >= 10 && trimmed.All(c => c == '-'))
            {
                if (i > 0)
                {
                    string above = lines[i - 1].Trim();
                    currentName = LooksLikeDomain(above) ? above : null;
                }
                continue;
            }

            if (currentName == null) continue;

            // Locale-independent label/value separator: ` : ` (space-colon-space). Tokens before
            // this are the localized label ("Record Name . . . . . :", "A (Host) Record . . . :",
            // etc.); tokens after are the value, which for A/AAAA records is the IP literal.
            int sep = line.IndexOf(" : ", StringComparison.Ordinal);
            if (sep < 0) continue;
            string value = line.Substring(sep + 3).Trim();
            if (value.Length == 0) continue;

            // Numeric-only values (TTL, type, length) cannot be IPs. IPv4 needs `.`, IPv6 needs
            // `:` — cheap reject before invoking IPAddress.TryParse.
            if (value.IndexOf('.') < 0 && value.IndexOf(':') < 0) continue;

            if (IPAddress.TryParse(value, out IPAddress? ip))
            {
                lock (_lock)
                {
                    if (!_map.TryGetValue(ip, out HashSet<string>? set))
                    {
                        set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        _map[ip] = set;
                    }
                    set.Add(currentName);
                }
            }
        }
    }

    private static bool LooksLikeDomain(string s)
    {
        if (string.IsNullOrEmpty(s)) return false;
        if (s.Length < 3) return false;
        if (s.IndexOf(' ') >= 0) return false;
        if (s.IndexOf(':') >= 0) return false;
        foreach (char c in s) if (char.IsLetter(c)) return true;
        return false;
    }

    public void Dispose()
    {
        try { _cts.Cancel(); } catch { }
        try { _loopTask?.Wait(TimeSpan.FromSeconds(2)); } catch { }
        _cts.Dispose();
    }
}
