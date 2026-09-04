using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace TqkLibrary.WinDivert.SecureDns.DependencyInjection;

/// <summary>Registers the DNS pieces the redirect pipeline can use.</summary>
public static class SecureDnsServiceCollectionExtensions
{
    /// <summary>
    /// Adds the message parser, the reverse-DNS table and the DoH resolver factory. The middlewares
    /// themselves are not registered: each one binds to the socket tracker and table of a single
    /// session, so they are built when a redirect session starts, not when the container is.
    /// </summary>
    public static IServiceCollection AddWinDivertSecureDns(this IServiceCollection services)
    {
        if (services is null) throw new ArgumentNullException(nameof(services));

        services.TryAddSingleton<IDnsMessageParser, DnsMessageParser>();
        services.TryAddSingleton<IDnsResolverFactory, DohResolverFactory>();
        // Transient: a table accumulates what the processes of one session resolved, and two
        // sessions should not read each other names.
        services.TryAddTransient<IReverseDnsTable, ReverseDnsTable>();
        return services;
    }
}
