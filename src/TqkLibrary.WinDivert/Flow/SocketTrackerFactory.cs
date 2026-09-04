using System;
using Microsoft.Extensions.Logging;

namespace TqkLibrary.WinDivert.Flow;

/// <summary>Creates <see cref="SocketTracker"/> instances with the container's driver and logging.</summary>
public sealed class SocketTrackerFactory : ISocketTrackerFactory
{
    private readonly IWinDivertHandleFactory _handleFactory;
    private readonly ILoggerFactory _loggerFactory;

    public SocketTrackerFactory(IWinDivertHandleFactory handleFactory, ILoggerFactory loggerFactory)
    {
        _handleFactory = handleFactory ?? throw new ArgumentNullException(nameof(handleFactory));
        _loggerFactory = loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory));
    }

    public ISocketTracker Create(uint processId, short socketPriority = 0)
        => new SocketTracker(processId, _handleFactory, _loggerFactory.CreateLogger<SocketTracker>(), socketPriority);
}
