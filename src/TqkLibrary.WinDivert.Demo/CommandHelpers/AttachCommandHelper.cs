using System;
using System.CommandLine;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.WinDivert.Redirect;

namespace TqkLibrary.WinDivert.Demo.CommandHelpers;

internal sealed class AttachCommandHelper : ICommandHelper
{
    private readonly Command _command;
    private readonly Option<string?> _processOpt;
    private readonly Option<string?> _protocolOpt;
    private readonly Option<bool> _waitOpt;
    private readonly Option<int> _waitTimeoutOpt;
    private readonly Option<bool> _exitWhenGoneOpt;
    private readonly Option<bool> _suspendOnAttachOpt;
    private readonly Option<bool> _followChildrenOpt;

    public Command Command => _command;

    public AttachCommandHelper()
    {
        _command = new Command("attach", "Attach the redirector to an existing process.");

        _processOpt = new Option<string?>("--process")
        {
            Description = "Pick process by exact PID or substring of name. If omitted, prompts interactively.",
        };
        _protocolOpt = new Option<string?>("--protocol")
        {
            Description = "Protocol to redirect: t=TCP, u=UDP, b=both. If omitted, prompts interactively.",
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
        _suspendOnAttachOpt = new Option<bool>("--suspend-on-attach")
        {
            Description = "Freeze the running process until the tracker is ready, then resume. Eliminates the SYN-race leak. WARNING: a kernel-mode anti-cheat may flag the freeze.",
        };
        _followChildrenOpt = new Option<bool>("--follow-children")
        {
            Description = "Track every descendant process spawned by the target (polled every 500ms).",
        };

        _command.Options.Add(_processOpt);
        _command.Options.Add(_protocolOpt);
        _command.Options.Add(_waitOpt);
        _command.Options.Add(_waitTimeoutOpt);
        _command.Options.Add(_exitWhenGoneOpt);
        _command.Options.Add(_suspendOnAttachOpt);
        _command.Options.Add(_followChildrenOpt);

        _command.SetAction(InvokeAsync);
    }

    private async Task<int> InvokeAsync(ParseResult parseResult, CancellationToken ct)
    {
        string? processSelector = parseResult.GetValue(_processOpt);
        string? protocolText = parseResult.GetValue(_protocolOpt);
        bool wait = parseResult.GetValue(_waitOpt);
        int waitTimeout = parseResult.GetValue(_waitTimeoutOpt);
        bool exitWhenGone = parseResult.GetValue(_exitWhenGoneOpt);
        bool suspendOnAttach = parseResult.GetValue(_suspendOnAttachOpt);
        bool followChildren = parseResult.GetValue(_followChildrenOpt);

        RedirectProtocol? protocol = null;
        if (protocolText != null)
        {
            protocol = ProtocolParser.Parse(protocolText);
            if (protocol == null)
            {
                Console.WriteLine($"Invalid value for --protocol: '{protocolText}' (expected t|u|b).");
                return 2;
            }
        }

        uint? pid = await ProcessResolver.ResolveAsync(processSelector, wait, waitTimeout, ct).ConfigureAwait(false);
        if (pid == null) return 0;

        RedirectProtocol proto = protocol ?? ProtocolParser.SelectInteractive();
        if (proto == RedirectProtocol.None) return 0;

        SuspendedProcessLauncher.SuspendedProcess? attachSuspended = null;
        if (suspendOnAttach)
        {
            try
            {
                attachSuspended = SuspendedProcessLauncher.AttachSuspend(pid.Value);
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
            return await RedirectorRunner.RunAsync(pid.Value, proto, exitWhenGone, attachSuspended, followChildren, ct).ConfigureAwait(false);
        }
        finally
        {
            attachSuspended?.Dispose();
        }
    }
}
