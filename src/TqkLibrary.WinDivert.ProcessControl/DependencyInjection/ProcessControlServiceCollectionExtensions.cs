using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace TqkLibrary.WinDivert.ProcessControl.DependencyInjection;

/// <summary>Registers process discovery, suspended launching, and child-process tracking.</summary>
public static class ProcessControlServiceCollectionExtensions
{
    /// <summary>
    /// Adds the process-control services. Nothing here touches the WinDivert driver, so it is
    /// usable — and testable — without Administrator rights.
    /// </summary>
    public static IServiceCollection AddWinDivertProcessControl(this IServiceCollection services)
    {
        if (services is null) throw new ArgumentNullException(nameof(services));

        services.TryAddSingleton<IProcessFinder, ProcessFinder>();
        services.TryAddSingleton<ISuspendedProcessLauncher, SuspendedProcessLauncher>();
        services.TryAddSingleton<IProcessTreeMonitorFactory, ProcessTreeMonitorFactory>();
        return services;
    }
}
