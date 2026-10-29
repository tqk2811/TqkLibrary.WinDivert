using System;
using Microsoft.Extensions.Logging;
using TqkLibrary.WinDivert.Pipeline.Models;

namespace TqkLibrary.WinDivert.Pipeline;

/// <summary>Builds <see cref="PacketPump"/> instances with the container's parser and logging.</summary>
public sealed class PacketPumpFactory : IPacketPumpFactory
{
    private readonly IPacketParser _parser;
    private readonly ILoggerFactory _loggerFactory;
    private readonly PumpLatencyAlertOptions? _latencyAlert;

    public PacketPumpFactory(IPacketParser parser, ILoggerFactory loggerFactory, PumpLatencyAlertOptions? latencyAlert = null)
    {
        _parser = parser ?? throw new ArgumentNullException(nameof(parser));
        _loggerFactory = loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory));
        _latencyAlert = latencyAlert;
    }

    public IPacketPump Create(string name, IWinDivertHandle handle, PacketDelegate pipeline)
        => Create(name, handle, pipeline, bypass: null);

    public IPacketPump Create(string name, IWinDivertHandle handle, PacketDelegate pipeline, IPacketBypass? bypass)
        => new PacketPump(name, handle, pipeline, _parser, _loggerFactory.CreateLogger<PacketPump>(), bypass, _latencyAlert);
}
