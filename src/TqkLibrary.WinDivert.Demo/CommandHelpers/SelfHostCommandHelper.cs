using System;
using System.CommandLine;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.Proxy;
using TqkLibrary.Proxy.Authentications;
using TqkLibrary.Proxy.Handlers;
using TqkLibrary.Proxy.Interfaces;
using TqkLibrary.Proxy.ProxySources;

namespace TqkLibrary.WinDivert.Demo.CommandHelpers;

// End-to-end self-hosted scenario:
//   target process -> WinDivert -> HttpProxySource (client side, in this demo)
//                  -> TqkLibrary.Proxy.ProxyServer (server side, this demo, 127.0.0.1:ephemeral)
//                  -> LocalProxySource (backend) -> internet
internal sealed class SelfHostCommandHelper : ICommandHelper
{
    private readonly Command _command;
    private readonly Option<string?> _processOpt;
    private readonly Option<bool> _waitOpt;
    private readonly Option<int> _waitTimeoutOpt;
    private readonly Option<bool> _exitWhenGoneOpt;
    private readonly Option<string?> _launchExeOpt;
    private readonly Option<string?> _launchArgsOpt;
    private readonly Option<string?> _authOpt;
    private readonly Option<int> _serverPortOpt;

    public Command Command => _command;

    public SelfHostCommandHelper()
    {
        _command = new Command("selfhost",
            "Self-host an HTTP ProxyServer (TqkLibrary.Proxy) backed by LocalProxySource, then redirect the target process through it via WinDivert.");

        _processOpt = new Option<string?>("--process")
        {
            Description = "Pick existing process by PID or name substring. Mutually exclusive with --launch.",
        };
        _waitOpt = new Option<bool>("--wait")
        {
            Description = "Poll until --process is found.",
        };
        _waitTimeoutOpt = new Option<int>("--wait-timeout")
        {
            Description = "Max wait time (seconds) when --wait is set.",
            DefaultValueFactory = _ => 60,
        };
        _exitWhenGoneOpt = new Option<bool>("--exit-when-process-gone")
        {
            Description = "Exit when target process terminates.",
        };
        _launchExeOpt = new Option<string?>("--launch")
        {
            Description = "Launch executable suspended; redirector attaches before resume.",
        };
        _launchArgsOpt = new Option<string?>("--launch-args")
        {
            Description = "Command-line arguments for --launch.",
        };
        _authOpt = new Option<string?>("--auth")
        {
            Description = "Optional Basic auth in 'user:pass' form. Hosted server will require it and the client side will present it.",
        };
        _serverPortOpt = new Option<int>("--server-port")
        {
            Description = "TCP port for the self-hosted proxy server (0 = ephemeral).",
            DefaultValueFactory = _ => 0,
        };

        _command.Options.Add(_processOpt);
        _command.Options.Add(_waitOpt);
        _command.Options.Add(_waitTimeoutOpt);
        _command.Options.Add(_exitWhenGoneOpt);
        _command.Options.Add(_launchExeOpt);
        _command.Options.Add(_launchArgsOpt);
        _command.Options.Add(_authOpt);
        _command.Options.Add(_serverPortOpt);

        _command.SetAction(InvokeAsync);
    }

    private async Task<int> InvokeAsync(ParseResult parseResult, CancellationToken ct)
    {
        string? processSelector = parseResult.GetValue(_processOpt);
        bool wait = parseResult.GetValue(_waitOpt);
        int waitTimeout = parseResult.GetValue(_waitTimeoutOpt);
        bool exitWhenGone = parseResult.GetValue(_exitWhenGoneOpt);
        string? launchExe = parseResult.GetValue(_launchExeOpt);
        string? launchArgs = parseResult.GetValue(_launchArgsOpt);
        string? auth = parseResult.GetValue(_authOpt);
        int serverPort = parseResult.GetValue(_serverPortOpt);

        if (launchExe != null && processSelector != null)
        {
            Console.WriteLine("--launch and --process are mutually exclusive.");
            return 2;
        }

        HttpProxyAuthentication? credential = null;
        if (!string.IsNullOrWhiteSpace(auth))
        {
            int sep = auth!.IndexOf(':');
            if (sep <= 0 || sep == auth.Length - 1)
            {
                Console.WriteLine("--auth must be in 'user:pass' format.");
                return 2;
            }
            credential = new HttpProxyAuthentication(auth.Substring(0, sep), auth.Substring(sep + 1));
        }

        var local = new LocalProxySource();
        var handler = credential is null
            ? new BaseProxyServerHandler(local)
            : (BaseProxyServerHandler)new RequireBasicAuthHandler(local, credential);

        using var server = new ProxyServer(new IPEndPoint(IPAddress.Loopback, serverPort), local)
        {
            ProxyServerHandler = handler,
        };
        server.StartListen();
        IPEndPoint? listenEp = server.IPEndPoint;
        if (listenEp == null)
        {
            Console.WriteLine("Self-hosted ProxyServer failed to bind.");
            return 1;
        }
        Console.WriteLine($"Self-hosted HTTP proxy : http://{listenEp}  (backend = LocalProxySource){(credential is null ? "" : "  [auth required]")}");

        var clientUri = new Uri($"http://{listenEp}");
        var clientSource = new HttpProxySource(clientUri);
        if (credential != null) clientSource.HttpProxyAuthentication = credential;

        string proxyDisplay = credential is null
            ? clientUri.ToString()
            : $"http://***:***@{listenEp}";

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
                return await ProxyRedirectorRunner.RunAsync(
                    suspended.Pid, clientSource, proxyDisplay,
                    exitWhenProcessGone: true,
                    resumeBeforeRun: suspended,
                    ct).ConfigureAwait(false);
            }
            finally
            {
                suspended?.Dispose();
            }
        }

        uint? pid = await ProcessResolver.ResolveAsync(processSelector, wait, waitTimeout, ct).ConfigureAwait(false);
        if (pid == null) return 0;

        return await ProxyRedirectorRunner.RunAsync(
            pid.Value, clientSource, proxyDisplay,
            exitWhenGone,
            resumeBeforeRun: null,
            ct).ConfigureAwait(false);
    }

    private sealed class RequireBasicAuthHandler : BaseProxyServerHandler
    {
        private readonly HttpProxyAuthentication _expected;
        public RequireBasicAuthHandler(IProxySource source, HttpProxyAuthentication expected) : base(source)
        {
            _expected = expected;
        }
        public override Task<bool> IsAcceptUserAsync(IUserInfo userInfo, CancellationToken cancellationToken = default)
        {
            if (userInfo.Authentication is HttpProxyAuthentication a)
                return Task.FromResult(a.Equals(_expected));
            return Task.FromResult(false);
        }
    }
}
