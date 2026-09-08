using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using TqkLibrary.WinDivert.Flow;
using TqkLibrary.WinDivert.Native;
using TqkLibrary.WinDivert.Packet;
using TqkLibrary.WinDivert.Pipeline;

namespace TqkLibrary.WinDivert.DependencyInjection;

/// <summary>
/// Registers the WinDivert core: the driver, the packet parser, and the factories that build
/// pumps and socket trackers for one redirect session.
/// </summary>
public static class WinDivertServiceCollectionExtensions
{
    /// <summary>
    /// Adds the core services. Everything is registered with TryAdd, so a host that wants to
    /// substitute a piece — a fake <see cref="IWinDivertHandleFactory"/> in a test, say — just
    /// registers its own first.
    /// </summary>
    /// <remarks>
    /// The host must also have called AddLogging (or registered an <c>ILoggerFactory</c>): these
    /// services log through <c>ILogger&lt;T&gt;</c> and have no sink of their own.
    /// </remarks>
    public static IServiceCollection AddWinDivert(this IServiceCollection services)
    {
        if (services is null) throw new ArgumentNullException(nameof(services));

        services.TryAddSingleton<IWinDivertHandleFactory, WinDivertHandleFactory>();
        services.TryAddSingleton<IPacketParser, PacketParser>();
        services.TryAddSingleton<IPacketPumpFactory, PacketPumpFactory>();
        services.TryAddSingleton<ISocketTrackerFactory, SocketTrackerFactory>();
        // A factory, not the service itself. The lookup owns a polling task and is disposed with
        // the session that asked for it — and a transient IDisposable resolved from the ROOT
        // provider is added to that provider's own disposables list, which holds a strong
        // reference until the application exits. Every start/stop cycle left another lookup there,
        // still holding its map, which only ever grows.
        //
        // Registering a Func of your own is how to substitute an implementation.
        Func<IDnsCacheLookup> dnsCacheLookupFactory = () => new DnsCacheLookup();
        services.TryAddSingleton(dnsCacheLookupFactory);
        return services;
    }
}
