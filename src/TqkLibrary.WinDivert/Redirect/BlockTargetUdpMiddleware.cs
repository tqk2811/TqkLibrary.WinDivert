using System.Threading.Tasks;
using TqkLibrary.WinDivert.Packet;
using TqkLibrary.WinDivert.Pipeline;

namespace TqkLibrary.WinDivert.Redirect;

// Terminal "block" middleware: drops the target process's outbound IPv4 UDP that no earlier
// middleware claimed. Place it LAST in the IPv4 pipeline so stages like DnsOverHttpsMiddleware get
// first crack at the packets they handle (e.g. DNS/53); whatever falls through to here is swallowed.
//
// This is the safe form of "if no middleware handles it, drop": the scope is narrowed to the
// target's own outbound real-interface UDP, so non-target traffic and the NAT loopback-reply leg
// (already claimed by NatRedirectMiddleware) are never affected. Used when the proxy carrying the
// target's traffic cannot tunnel UDP and we must not let UDP leak out direct.
public sealed class BlockTargetUdpMiddleware : IPacketMiddleware
{
    public Task InvokeAsync(PacketContext ctx, PacketDelegate next)
    {
        ParsedPacket? p = ctx.Packet;
        if (p != null && p.IsUdp && !p.IsIpv6
            && ctx.Address.Outbound && !ctx.Address.Loopback
            && ctx.Tracker.IsTrackedUdp(p.Source, p.SourcePort))
        {
            ctx.Logger.Log("UDX", $"DROP udp {p.Source}:{p.SourcePort} -> {p.Destination}:{p.DestinationPort} len={ctx.Length}");
            ctx.Drop();
            return Task.CompletedTask;
        }
        return next(ctx);
    }
}
