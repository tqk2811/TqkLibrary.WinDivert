using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using TqkLibrary.WinDivert.DependencyInjection;
using TqkLibrary.WinDivert.Inspection.DependencyInjection;
using TqkLibrary.WinDivert.SecureDns.DependencyInjection;

namespace TqkLibrary.WinDivert.Redirect.DependencyInjection;

/// <summary>
/// Registers process-targeted redirection and everything it stands on.
/// </summary>
public static class RedirectServiceCollectionExtensions
{
    /// <summary>
    /// Adds the redirect stack: the core driver services, the DNS services, host-name inspection,
    /// and the factory that builds a redirect session.
    /// </summary>
    /// <remarks>
    /// The host still supplies logging (AddLogging, or its own <c>ILoggerFactory</c>). Nothing
    /// here writes a log file or holds a sink of its own — where the lines go is the host's call,
    /// which is why an <c>ILoggerProvider</c> is the one thing this library asks for and does not
    /// provide.
    ///
    /// A redirect session is NOT registered as a service: it owns driver handles and sockets, is
    /// configured per run, and must be disposed by whoever started it. Ask
    /// <see cref="Interfaces.IProcessRedirectorFactory"/> for one instead.
    /// </remarks>
    public static IServiceCollection AddWinDivertRedirect(this IServiceCollection services)
    {
        if (services is null) throw new ArgumentNullException(nameof(services));

        services.AddWinDivert();
        services.AddWinDivertSecureDns();
        services.AddWinDivertInspection();

        services.TryAddSingleton<IProcessRedirectorFactory>(sp => new ProcessRedirectorFactory(
            sp.GetRequiredService<IWinDivertHandleFactory>(),
            sp.GetRequiredService<ISocketTrackerFactory>(),
            sp.GetRequiredService<IPacketPumpFactory>(),
            sp.GetRequiredService<IDnsMessageParser>(),
            sp.GetRequiredService<IDnsResolverFactory>(),
            sp.GetRequiredService<IReverseDnsTable>,
            sp.GetRequiredService<IDnsCacheLookup>,
            sp.GetRequiredService<Microsoft.Extensions.Logging.ILoggerFactory>()));

        // Resolves without a reverse-DNS table: the one that matters belongs to a session, and a
        // caller that wants it asks the session for its table and builds its own resolver.
        services.TryAddSingleton<IConnectionHostNameResolver>(sp =>
            new ConnectionHostNameResolver(sp.GetRequiredService<IHostNameInspector>()));

        return services;
    }
}
