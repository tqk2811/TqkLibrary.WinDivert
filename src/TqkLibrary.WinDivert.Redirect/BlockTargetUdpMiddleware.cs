using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace TqkLibrary.WinDivert.Redirect;

/// <summary>
/// Terminal "block" stage: drops the target process's outbound UDP that no earlier middleware
/// claimed. Place it LAST, so stages like DNS-over-HTTPS get first crack at the packets they
/// handle; whatever falls through to here is swallowed.
/// </summary>
/// <remarks>
/// This is the safe form of "if no middleware handles it, drop": the scope is narrowed to the
/// target's own outbound real-interface UDP, so other processes and the NAT loopback-reply leg
/// (already claimed upstream) are never affected. Use it when the proxy carrying the target's
/// traffic cannot tunnel UDP and UDP must not leak out direct.
///
/// Family-agnostic — the pipeline it is registered in decides whether it sees IPv4 or IPv6.
/// </remarks>
public sealed class BlockTargetUdpMiddleware : IPacketMiddleware
{
    private readonly ISocketTracker _tracker;
    private readonly ILogger<BlockTargetUdpMiddleware> _logger;

    public BlockTargetUdpMiddleware(ISocketTracker tracker, ILogger<BlockTargetUdpMiddleware> logger)
    {
        _tracker = tracker ?? throw new ArgumentNullException(nameof(tracker));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public Task InvokeAsync(PacketContext ctx, PacketDelegate next)
    {
        ParsedPacket? p = ctx.Packet;
        if (p != null && p.IsUdp
            && ctx.Address.Outbound && !ctx.Address.Loopback
            && _tracker.IsTrackedUdp(p.Source, p.SourcePort))
        {
            _logger.LogTrace("dropping udp {Source}:{SourcePort} -> {Destination}:{DestinationPort} len={Length}",
                p.Source, p.SourcePort, p.Destination, p.DestinationPort, ctx.Length);
            ctx.Drop();
            return Task.CompletedTask;
        }
        return next(ctx);
    }
}
