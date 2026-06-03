using System;
using System.Net;
using System.Threading.Tasks;
using TqkLibrary.WinDivert.Flow;
using TqkLibrary.WinDivert.Pipeline;

namespace TqkLibrary.WinDivert.Redirect;

// The IPv4 NAT pipeline only sees IPv4, so any IPv6 traffic of the target would otherwise be
// emitted by the kernel direct — leaking the real client IPv6 address. This middleware runs on a
// parallel IPv6 NETWORK-layer pump, drops packets belonging to the target process, and defers
// everything else to next() (→ Pass terminal) so other processes keep working.
//
// Parsing is intentionally minimal: no IPv6 extension headers are walked. Almost all user-mode
// application traffic uses NextHeader=TCP(6) / UDP(17) directly; if extension headers are present
// we conservatively pass the packet through (rather than mis-parsing and blocking unrelated
// traffic). It parses ctx.Buffer itself rather than relying on ctx.Packet to preserve that exact
// conservative behavior.
public sealed class Ipv6BlockMiddleware : IPacketMiddleware
{
    public Task InvokeAsync(PacketContext ctx, PacketDelegate next)
    {
        if (ShouldDrop(ctx))
        {
            ctx.Drop();
            return Task.CompletedTask;
        }
        return next(ctx);
    }

    // Returns true if the packet belongs to the tracked process and should be dropped.
    // Returns false for non-target traffic or for packets we cannot confidently parse.
    private static bool ShouldDrop(PacketContext ctx)
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

        // Localise to the target's perspective: the tracker's keys store (local, remote) where
        // "local" is the target side. Outbound packets put the target as source; inbound packets
        // put the target as destination.
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
            ? ctx.Tracker.IsTrackedTcp(new FlowKey(6, localIp, localPort, remoteIp, remotePort))
            : ctx.Tracker.IsTrackedUdp(localIp, localPort);

        if (target)
        {
            DiagnosticLogger.Log("V6X",
                $"DROP {(ctx.Address.Outbound ? "out" : "in")} {(nextHeader == 6 ? "tcp" : "udp")} {srcIp}:{srcPort} -> {dstIp}:{dstPort} len={length}");
        }
        return target;
    }
}
