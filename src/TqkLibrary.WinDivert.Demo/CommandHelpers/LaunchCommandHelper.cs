using System;
using System.CommandLine;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.WinDivert.Redirect;

namespace TqkLibrary.WinDivert.Demo.CommandHelpers;

internal sealed class LaunchCommandHelper : ICommandHelper
{
    private readonly Command _command;
    private readonly Argument<string> _exeArg;
    private readonly Option<string?> _argsOpt;
    private readonly Option<string?> _protocolOpt;

    public Command Command => _command;

    public LaunchCommandHelper()
    {
        _command = new Command("launch", "Launch an executable suspended, attach the redirector, then resume.");

        _exeArg = new Argument<string>("exe")
        {
            Description = "Path to the executable to launch (e.g. curl.exe).",
        };
        _argsOpt = new Option<string?>("--args")
        {
            Description = "Command-line arguments string passed to the launched process.",
        };
        _protocolOpt = new Option<string?>("--protocol")
        {
            Description = "Protocol to redirect: t=TCP, u=UDP, b=both. Default: t.",
            DefaultValueFactory = _ => "t",
        };

        _command.Arguments.Add(_exeArg);
        _command.Options.Add(_argsOpt);
        _command.Options.Add(_protocolOpt);

        _command.SetAction(InvokeAsync);
    }

    private async Task<int> InvokeAsync(ParseResult parseResult, CancellationToken ct)
    {
        string exe = parseResult.GetValue(_exeArg)!;
        string? args = parseResult.GetValue(_argsOpt);
        string protocolText = parseResult.GetValue(_protocolOpt) ?? "t";

        RedirectProtocol? proto = ProtocolParser.Parse(protocolText);
        if (proto == null)
        {
            Console.WriteLine($"Invalid value for --protocol: '{protocolText}' (expected t|u|b).");
            return 2;
        }

        SuspendedProcessLauncher.SuspendedProcess? suspended = null;
        try
        {
            try
            {
                suspended = SuspendedProcessLauncher.Launch(exe, args);
                Console.WriteLine($"Launched (suspended) pid={suspended.Pid}: \"{exe}\" {args}");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Failed to launch process: " + ex.Message);
                return 1;
            }

            return await RedirectorRunner.RunAsync(suspended.Pid, proto.Value, exitWhenProcessGone: true, suspended, ct).ConfigureAwait(false);
        }
        finally
        {
            suspended?.Dispose();
        }
    }
}
