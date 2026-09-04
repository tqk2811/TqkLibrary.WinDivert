using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace TqkLibrary.WinDivert.Inspection.DependencyInjection;

/// <summary>Registers the host-name inspection stack.</summary>
public static class InspectionServiceCollectionExtensions
{
    /// <summary>
    /// Adds <see cref="IHostNameInspector"/> and the built-in parsers behind it. Registering a
    /// further <see cref="IHostNameParser"/> before or after this call adds it to the set the
    /// inspector consults — the built-ins are added with TryAddEnumerable, so calling this twice
    /// does not duplicate them.
    /// </summary>
    public static IServiceCollection AddWinDivertInspection(this IServiceCollection services)
    {
        if (services is null) throw new ArgumentNullException(nameof(services));

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostNameParser, TlsClientHelloParser>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostNameParser, HttpHostParser>());
        services.TryAddSingleton<IHostNameInspector, HostNameInspector>();
        return services;
    }
}
