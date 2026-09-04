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
        // Transient: it owns a polling task, and a caller that asks for one is expected to
        // dispose it with the session it belongs to.
        services.TryAddTransient<IDnsCacheLookup, DnsCacheLookup>();
        return services;
    }
}
