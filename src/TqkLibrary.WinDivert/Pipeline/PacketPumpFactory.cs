using System;
using Microsoft.Extensions.Logging;

namespace TqkLibrary.WinDivert.Pipeline;

/// <summary>Builds <see cref="PacketPump"/> instances with the container's parser and logging.</summary>
public sealed class PacketPumpFactory : IPacketPumpFactory
{
    private readonly IPacketParser _parser;
    private readonly ILoggerFactory _loggerFactory;

    public PacketPumpFactory(IPacketParser parser, ILoggerFactory loggerFactory)
    {
        _parser = parser ?? throw new ArgumentNullException(nameof(parser));
        _loggerFactory = loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory));
    }

    public IPacketPump Create(string name, IWinDivertHandle handle, PacketDelegate pipeline)
        => new PacketPump(name, handle, pipeline, _parser, _loggerFactory.CreateLogger<PacketPump>());
}
