using System;
using System.Net;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace TqkLibrary.WinDivert.Redirect;

/// <summary>
/// Drops the target process's IPv6 traffic, so an application that finds IPv6 unusable falls back
/// to IPv4 — which the redirector does capture. Everything belonging to other processes is passed
/// on untouched.
/// </summary>
/// <remarks>
/// This is the fallback when IPv6 cannot be redirected: an IPv4-only NAT pipeline would otherwise
/// let the kernel emit the target's IPv6 direct, leaking the real client address.
///
/// Parsing is intentionally minimal: no IPv6 extension headers are walked. Almost all user-mode
/// application traffic uses NextHeader=TCP(6)/UDP(17) directly; when extension headers ARE present
/// the packet is passed through rather than mis-parsed and blocked. It reads the buffer itself
/// rather than ctx.Packet precisely to keep that conservative reading.
/// </remarks>
public sealed class Ipv6BlockMiddleware : IPacketMiddleware
{
    private readonly ISocketTracker _tracker;
    private readonly ILogger<Ipv6BlockMiddleware> _logger;

    public Ipv6BlockMiddleware(ISocketTracker tracker, ILogger<Ipv6BlockMiddleware> logger)
    {
        _tracker = tracker ?? throw new ArgumentNullException(nameof(tracker));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public Task InvokeAsync(PacketContext ctx, PacketDelegate next)
    {
        if (ShouldDrop(ctx))
        {
            ctx.Drop();
            return Task.CompletedTask;
        }
        return next(ctx);
    }

    // True when the packet belongs to a tracked process and should be dropped. False for other
    // traffic, and for packets that cannot be parsed with confidence.
    private bool ShouldDrop(PacketContext ctx)
    {
        byte[] buffer = ctx.Buffer;
        int length = ctx.Length;

        // Minimum IPv6 (40) + TCP/UDP port pair (4).
        if (length < 44) return false;
        if ((buffer[0] >> 4) != 6) return false;

        byte nextHeader = buffer[6];
        if (nextHeader != 6 && nextHeader != 17) return false;

        byte[] srcBytes = new byte[16];
        byte[] dstBytes = new byte[16];
        Buffer.BlockCopy(buffer, 8, srcBytes, 0, 16);
        Buffer.BlockCopy(buffer, 24, dstBytes, 0, 16);
        IPAddress srcIp = new IPAddress(srcBytes);
        IPAddress dstIp = new IPAddress(dstBytes);

        ushort srcPort = (ushort)((buffer[40] << 8) | buffer[41]);
        ushort dstPort = (ushort)((buffer[42] << 8) | buffer[43]);

        // Localise to the target's perspective: the tracker keys store (local, remote) where
        // "local" is the target side. Outbound packets put the target as source; inbound packets
        // put it as destination.
        IPAddress localIp;
        ushort localPort;
        IPAddress remoteIp;
        ushort remotePort;
        if (ctx.Address.Outbound)
        {
            localIp = srcIp; localPort = srcPort;
            remoteIp = dstIp; remotePort = dstPort;
        }
        else
        {
            localIp = dstIp; localPort = dstPort;
            remoteIp = srcIp; remotePort = srcPort;
        }

        bool target = nextHeader == 6
            ? _tracker.IsTrackedTcp(new FlowKey(6, localIp, localPort, remoteIp, remotePort))
            : _tracker.IsTrackedUdp(localIp, localPort);

        if (target)
        {
            _logger.LogTrace("dropping {Direction} {Protocol} {Source}:{SourcePort} -> {Destination}:{DestinationPort} len={Length}",
                ctx.Address.Outbound ? "out" : "in", nextHeader == 6 ? "tcp" : "udp",
                srcIp, srcPort, dstIp, dstPort, length);
        }
        return target;
    }
}
