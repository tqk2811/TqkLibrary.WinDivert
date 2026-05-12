using System;
using System.CommandLine;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.Proxy.Interfaces;

namespace TqkLibrary.WinDivert.Demo.CommandHelpers;

internal sealed class ProxyCommandHelper : ICommandHelper
{
    private readonly Command _command;
    private readonly Option<string> _proxyOpt;
    private readonly Option<string?> _processOpt;
    private readonly Option<bool> _waitOpt;
    private readonly Option<int> _waitTimeoutOpt;
    private readonly Option<bool> _exitWhenGoneOpt;
    private readonly Option<string?> _launchExeOpt;
    private readonly Option<string?> _launchArgsOpt;

    public Command Command => _command;

    public ProxyCommandHelper()
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

        _command.Options.Add(_proxyOpt);
        _command.Options.Add(_processOpt);
        _command.Options.Add(_waitOpt);
        _command.Options.Add(_waitTimeoutOpt);
        _command.Options.Add(_exitWhenGoneOpt);
        _command.Options.Add(_launchExeOpt);
        _command.Options.Add(_launchArgsOpt);

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

        if (launchExe != null && processSelector != null)
        {
            Console.WriteLine("--launch and --process are mutually exclusive.");
            return 2;
        }

        IProxySource proxySource;
        string proxyDisplay = MaskUserInfo(proxyUrl);
        try
        {
            proxySource = ProxyUriParser.Parse(proxyUrl);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to parse --proxy '{proxyUrl}': {ex.Message}");
            return 2;
        }

        if (launchExe != null)
        {
            SuspendedProcessLauncher.SuspendedProcess? suspended = null;
            try
            {
                try
                {
                    suspended = SuspendedProcessLauncher.Launch(launchExe, launchArgs);
                    Console.WriteLine($"Launched (suspended) pid={suspended.Pid}: \"{launchExe}\" {launchArgs}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Failed to launch process: " + ex.Message);
                    return 1;
                }

                int rc = await ProxyRedirectorRunner.RunAsync(
                    suspended.Pid, proxySource, proxyDisplay,
                    exitWhenProcessGone: true,
                    resumeBeforeRun: suspended,
                    ct).ConfigureAwait(false);
                return rc;
            }
            finally
            {
                suspended?.Dispose();
            }
        }

        uint? pid = await ProcessResolver.ResolveAsync(processSelector, wait, waitTimeout, ct).ConfigureAwait(false);
        if (pid == null) return 0;

        return await ProxyRedirectorRunner.RunAsync(
            pid.Value, proxySource, proxyDisplay,
            exitWhenGone,
            resumeBeforeRun: null,
            ct).ConfigureAwait(false);
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
