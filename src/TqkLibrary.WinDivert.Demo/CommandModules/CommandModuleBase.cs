using System;
using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;

namespace TqkLibrary.WinDivert.Demo.CommandModules;

/// <summary>
/// What every command in this demo shares: the container the library was registered in, and the
/// handful of services each command reaches for.
/// </summary>
internal abstract class CommandModuleBase : ICommandModule
{
    protected IServiceProvider Services { get; }

    /// <summary>Starts a process frozen, or freezes a running one, before the redirector attaches.</summary>
    protected ISuspendedProcessLauncher Launcher { get; }

    /// <summary>Turns a --process value (a pid, a name fragment, or nothing) into a pid.</summary>
    protected ProcessResolver Resolver { get; }

    public abstract Command Command { get; }

    protected CommandModuleBase(IServiceProvider services)
    {
        Services = services ?? throw new ArgumentNullException(nameof(services));
        Launcher = services.GetRequiredService<ISuspendedProcessLauncher>();
        Resolver = new ProcessResolver(services.GetRequiredService<IProcessFinder>());
    }
}
