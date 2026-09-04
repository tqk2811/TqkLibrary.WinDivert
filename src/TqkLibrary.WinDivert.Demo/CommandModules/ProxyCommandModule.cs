using System;
using System.CommandLine;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TqkLibrary.Proxy.Interfaces;
using System.IO;

namespace TqkLibrary.WinDivert.Demo.CommandModules;

internal sealed class ProxyCommandModule : CommandModuleBase
{
    private readonly Command _command;
    private readonly Option<string> _proxyOpt;
    private readonly Option<string?> _processOpt;
    private readonly Option<bool> _waitOpt;
    private readonly Option<int> _waitTimeoutOpt;
    private readonly Option<bool> _exitWhenGoneOpt;
    private readonly Option<string?> _launchExeOpt;
    private readonly Option<string?> _launchArgsOpt;
    private readonly Option<bool> _suspendOnAttachOpt;
    private readonly Option<bool> _followChildrenOpt;
    private readonly Option<string?> _redirectPortsOpt;
    private readonly Option<bool> _noDnsResolveOpt;
    private readonly Option<bool> _secureDnsOpt;
    private readonly Option<string?> _dohOpt;

    public override Command Command => _command;

    public ProxyCommandModule(IServiceProvider services) : base(services)
    {
        _command = new Command("proxy", "Route TCP traffic of a process through an HTTP/SOCKS4/SOCKS5 proxy (using TqkLibrary.Proxy).");

        _proxyOpt = new Option<string>("--proxy")
        {
            Description = "Upstream proxy URL: http://[user:pass@]host:port, socks4[a]://[user@]host:port, socks5://[user:pass@]host:port.",
            Required = true,
        };
        _processOpt = new Option<string?>("--process")
        {
            Description = "Pick existing process by exact PID or substring of name. Mutually exclusive with --launch.",
        };
        _waitOpt = new Option<bool>("--wait")
        {
            Description = "Poll until --process is found instead of failing immediately.",
        };
        _waitTimeoutOpt = new Option<int>("--wait-timeout")
        {
            Description = "Max wait time (seconds) when --wait is set.",
            DefaultValueFactory = _ => 60,
        };
        _exitWhenGoneOpt = new Option<bool>("--exit-when-process-gone")
        {
            Description = "Exit automatically when target process terminates.",
        };
        _launchExeOpt = new Option<string?>("--launch")
        {
            Description = "Path to executable to launch suspended; redirector attaches before it runs. Mutually exclusive with --process.",
        };
        _launchArgsOpt = new Option<string?>("--launch-args")
        {
            Description = "Command-line arguments for --launch.",
        };
        _suspendOnAttachOpt = new Option<bool>("--suspend-on-attach")
        {
            Description = "Freeze the running process (NtSuspendProcess) until the tracker is ready, then resume. Eliminates the SYN-race leak when using --process. WARNING: a kernel-mode anti-cheat may flag the freeze.",
        };
        _followChildrenOpt = new Option<bool>("--follow-children")
        {
            Description = "Track every descendant process spawned by the target (polled every 500ms). Each child gets its own SocketTracker handle so its TCP/UDP traffic is redirected too.",
        };
        _redirectPortsOpt = new Option<string?>("--redirect-ports")
        {
            Description = "Comma-separated destination port whitelist (e.g. \"443\" or \"443,8080\"). When set, only outbound traffic to these ports is routed via the proxy; other ports flow direct to their real destination (NOT proxied, NOT IP-leak protected). Omit to redirect every port (default).",
        };
        _noDnsResolveOpt = new Option<bool>("--no-dns-resolve")
        {
            Description = "Disable IP -> domain name annotation in logs and console output (which reads `ipconfig /displaydns` every 15s in the background).",
        };
        _secureDnsOpt = new Option<bool>("--secure-dns")
        {
            Description = "Resolve the target's DNS over HTTPS (DoH) instead of forwarding UDP/53. The original query is dropped and a DoH answer is injected back — so DNS works even though HTTP/SOCKS4 proxies can't tunnel UDP. Non-DNS UDP is still dropped (no leak).",
        };
        _dohOpt = new Option<string?>("--doh")
        {
            Description = "DoH endpoint URL (https) used by --secure-dns. Default https://1.1.1.1/dns-query. Use an IP literal to avoid a bootstrap DNS lookup.",
        };

        _command.Options.Add(_proxyOpt);
        _command.Options.Add(_processOpt);
        _command.Options.Add(_waitOpt);
        _command.Options.Add(_waitTimeoutOpt);
        _command.Options.Add(_exitWhenGoneOpt);
        _command.Options.Add(_launchExeOpt);
        _command.Options.Add(_launchArgsOpt);
        _command.Options.Add(_suspendOnAttachOpt);
        _command.Options.Add(_followChildrenOpt);
        _command.Options.Add(_redirectPortsOpt);
        _command.Options.Add(_noDnsResolveOpt);
        _command.Options.Add(_secureDnsOpt);
        _command.Options.Add(_dohOpt);

        _command.SetAction(InvokeAsync);
    }

    private async Task<int> InvokeAsync(ParseResult parseResult, CancellationToken ct)
    {
        string proxyUrl = parseResult.GetValue(_proxyOpt)!;
        string? processSelector = parseResult.GetValue(_processOpt);
        bool wait = parseResult.GetValue(_waitOpt);
        int waitTimeout = parseResult.GetValue(_waitTimeoutOpt);
        bool exitWhenGone = parseResult.GetValue(_exitWhenGoneOpt);
        string? launchExe = parseResult.GetValue(_launchExeOpt);
        string? launchArgs = parseResult.GetValue(_launchArgsOpt);
        bool suspendOnAttach = parseResult.GetValue(_suspendOnAttachOpt);
        bool followChildren = parseResult.GetValue(_followChildrenOpt);
        string? redirectPortsRaw = parseResult.GetValue(_redirectPortsOpt);
        bool noDnsResolve = parseResult.GetValue(_noDnsResolveOpt);
        bool secureDns = parseResult.GetValue(_secureDnsOpt);
        string? dohRaw = parseResult.GetValue(_dohOpt);

        if (launchExe != null && processSelector != null)
        {
            Console.WriteLine("--launch and --process are mutually exclusive.");
            return 2;
        }

        Uri? dohEndpoint = null;
        if (!string.IsNullOrWhiteSpace(dohRaw))
        {
            if (!Uri.TryCreate(dohRaw, UriKind.Absolute, out dohEndpoint) || dohEndpoint.Scheme != Uri.UriSchemeHttps)
            {
                Console.WriteLine($"--doh must be an absolute https URL, got '{dohRaw}'.");
                return 2;
            }
            secureDns = true; // specifying an endpoint implies enabling secure DNS
        }

        ushort[]? redirectPorts = null;
        if (!string.IsNullOrWhiteSpace(redirectPortsRaw))
        {
            try
            {
                redirectPorts = redirectPortsRaw!
                    .Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(s => ushort.Parse(s.Trim()))
                    .Distinct()
                    .ToArray();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to parse --redirect-ports '{redirectPortsRaw}': {ex.Message}");
                return 2;
            }
            if (redirectPorts.Length == 0) redirectPorts = null;
        }

        IProxySource proxySource;
        string proxyDisplay = MaskUserInfo(proxyUrl);
        // TqkLibrary.Proxy logs through ILogger too, so it goes to the same place everything else
        // does — the host built one logging setup and both libraries write into it.
        ILoggerFactory loggerFactory = Services.GetRequiredService<ILoggerFactory>();
        try
        {
            proxySource = ProxyUriParser.Parse(proxyUrl, loggerFactory);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to parse --proxy '{proxyUrl}': {ex.Message}");
            return 2;
        }

        if (launchExe != null)
        {
            ISuspendedProcess? suspended = null;
            try
            {
                try
                {
                    suspended = Launcher.Launch(launchExe, launchArgs);
                    Console.WriteLine($"Launched (suspended) pid={suspended.Pid}: \"{launchExe}\" {launchArgs}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Failed to launch process: " + ex.Message);
                    return 1;
                }

                int rc = await new ProxyRedirectorRunner(Services).RunAsync(
                    suspended.Pid, proxySource, proxyDisplay,
                    exitWhenProcessGone: true,
                    resumeBeforeRun: suspended,

                    followChildren,
                    redirectPorts,
                    enableDnsLookup: !noDnsResolve,
                    secureDns,
                    dohEndpoint,

                    ct).ConfigureAwait(false);
                return rc;
            }
            finally
            {
                suspended?.Dispose();
            }
        }

        uint? pid = await Resolver.ResolveAsync(processSelector, wait, waitTimeout, ct).ConfigureAwait(false);
        if (pid == null) return 0;

        ISuspendedProcess? attachSuspended = null;
        if (suspendOnAttach)
        {
            try
            {
                attachSuspended = Launcher.AttachSuspend(pid.Value);
                Console.WriteLine($"Suspended running pid={pid} until tracker ready.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"--suspend-on-attach failed: {ex.Message}");
                return 1;
            }
        }
        try
        {
            return await new ProxyRedirectorRunner(Services).RunAsync(
                pid.Value, proxySource, proxyDisplay,
                exitWhenGone,
                resumeBeforeRun: attachSuspended,

                followChildren,
                redirectPorts,
                enableDnsLookup: !noDnsResolve,
                secureDns,
                dohEndpoint,

                ct).ConfigureAwait(false);
        }
        finally
        {
            attachSuspended?.Dispose();
        }
    }

    private static string MaskUserInfo(string url)
    {
        try
        {
            var u = new Uri(url);
            if (string.IsNullOrEmpty(u.UserInfo)) return url;
            var b = new UriBuilder(u) { UserName = "***", Password = "***" };
            return b.Uri.ToString();
        }
        catch { return url; }
    }
}
