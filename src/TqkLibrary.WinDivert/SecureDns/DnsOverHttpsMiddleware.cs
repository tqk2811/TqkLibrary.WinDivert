using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.WinDivert.Native;
using TqkLibrary.WinDivert.Packet;
using TqkLibrary.WinDivert.Pipeline;
using TqkLibrary.WinDivert.Redirect;

namespace TqkLibrary.WinDivert.SecureDns;

// Intercepts the target process's outbound IPv4 UDP/53 (classic DNS), resolves it over HTTPS via
// DohResolver, and injects the answer back to the process as an inbound UDP packet — so DNS keeps
// working even when the proxy carrying the rest of the traffic can't tunnel UDP (HTTP/SOCKS4).
//
// The original query is dropped immediately; the HTTPS round-trip + injection happen on a bounded
// background task (the recv pump must not block on network I/O). Everything the task needs is
// copied out of the shared pump buffer BEFORE InvokeAsync returns.
public sealed class DnsOverHttpsMiddleware : IPacketMiddleware
{
    private const ushort DnsPort = 53;

    private readonly DohResolver _resolver;
    private readonly SemaphoreSlim _concurrency;

    public DnsOverHttpsMiddleware(DohResolver resolver, int maxConcurrentQueries = 32)
    {
        _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
        if (maxConcurrentQueries < 1) maxConcurrentQueries = 1;
        _concurrency = new SemaphoreSlim(maxConcurrentQueries, maxConcurrentQueries);
    }

    public Task InvokeAsync(PacketContext ctx, PacketDelegate next)
    {
        ParsedPacket? p = ctx.Packet;
        // Scope: target process's outbound IPv4 UDP/53 on a real interface.
        if (p == null || !p.IsUdp || p.IsIpv6) return next(ctx);
        if (!ctx.Address.Outbound || ctx.Address.Loopback) return next(ctx);
        if (p.DestinationPort != DnsPort) return next(ctx);
        if (!ctx.Tracker.IsTrackedUdp(p.Source, p.SourcePort)) return next(ctx);

        // Copy the DNS query payload + the 5-tuple/interface out of the shared buffer NOW.
        int payloadOffset = p.Udp.PayloadOffset;
        int available = ctx.Length - payloadOffset;
        int udpPayloadLen = p.Udp.PayloadLength;
        int payloadLen = (udpPayloadLen >= 0 && udpPayloadLen < available) ? udpPayloadLen : available;
        if (payloadLen <= 0)
        {
            ctx.Drop();
            return Task.CompletedTask;
        }

        byte[] query = new byte[payloadLen];
        Buffer.BlockCopy(ctx.Buffer, payloadOffset, query, 0, payloadLen);

        IPAddress clientIp = p.Source;
        ushort clientPort = p.SourcePort;
        IPAddress serverIp = p.Destination;
        uint ifIdx = ctx.Address.Network.IfIdx;
        uint subIfIdx = ctx.Address.Network.SubIfIdx;
        IPacketInjector injector = ctx.Injector;
        CancellationToken token = ctx.CancellationToken;

        // Swallow the original query; the resolved answer is injected later (or never, on failure).
        ctx.Drop();

        _ = Task.Run(() => ResolveAndInjectAsync(query, clientIp, clientPort, serverIp, ifIdx, subIfIdx, injector, token));
        return Task.CompletedTask;
    }

    private async Task ResolveAndInjectAsync(
        byte[] query, IPAddress clientIp, ushort clientPort, IPAddress serverIp,
        uint ifIdx, uint subIfIdx, IPacketInjector injector, CancellationToken token)
    {
        try { await _concurrency.WaitAsync(token).ConfigureAwait(false); }
        catch (OperationCanceledException) { return; }

        try
        {
            byte[]? response = await _resolver.ResolveAsync(query, token).ConfigureAwait(false);
            if (response == null || response.Length == 0) return;

            byte[] packet = BuildInboundReply(serverIp, clientIp, clientPort, response);
            WinDivertAddress addr = BuildInboundAddress(ifIdx, subIfIdx);
            bool ok = injector.Inject(packet, packet.Length, addr);
            DiagnosticLogger.Log("DOH", $"{clientIp}:{clientPort} <- {serverIp}:{DnsPort} resp={response.Length}B inject={ok}");
        }
        catch (Exception ex)
        {
            DiagnosticLogger.Log("DOH", $"inject failed: {ex.GetType().Name}: {ex.Message}");
        }
        finally
        {
            _concurrency.Release();
        }
    }

    // Builds a fresh IPv4/UDP datagram delivering `responseWire` FROM the DNS server (src=53) TO
    // the client's ephemeral port. Checksums are left zero; the injector recomputes them.
    private static byte[] BuildInboundReply(IPAddress serverIp, IPAddress clientIp, ushort clientPort, byte[] responseWire)
    {
        const int ipHeaderLen = 20;
        const int udpHeaderLen = 8;
        int total = ipHeaderLen + udpHeaderLen + responseWire.Length;
        byte[] buf = new byte[total];

        // ---- IPv4 header ----
        buf[0] = 0x45;                 // version 4, IHL 5 (no options)
        buf[1] = 0x00;                 // DSCP/ECN
        buf[2] = (byte)(total >> 8);   // Total Length (no Ipv4HeaderView setter — write manually)
        buf[3] = (byte)total;
        // [4..7] identification + flags/fragment = 0
        buf[8] = 64;                   // TTL
        buf[9] = 17;                   // protocol = UDP
        // [10..11] header checksum = 0 (filled by CalcChecksums)
        WriteIpv4(buf, 12, serverIp);  // source = DNS server
        WriteIpv4(buf, 16, clientIp);  // destination = client

        // ---- UDP header ----
        int udp = ipHeaderLen;
        buf[udp + 0] = (byte)(DnsPort >> 8);     // source port = 53
        buf[udp + 1] = (byte)DnsPort;
        buf[udp + 2] = (byte)(clientPort >> 8);  // destination port = client ephemeral
        buf[udp + 3] = (byte)clientPort;
        int udpLen = udpHeaderLen + responseWire.Length;
        buf[udp + 4] = (byte)(udpLen >> 8);      // UDP Length (no UdpHeaderView setter — manual)
        buf[udp + 5] = (byte)udpLen;
        // [udp+6..7] UDP checksum = 0 (filled by CalcChecksums)

        Buffer.BlockCopy(responseWire, 0, buf, ipHeaderLen + udpHeaderLen, responseWire.Length);
        return buf;
    }

    private static void WriteIpv4(byte[] buf, int at, IPAddress ip)
    {
        byte[] b = ip.GetAddressBytes();
        if (b.Length != 4) throw new ArgumentException("IPv4 address required", nameof(ip));
        Buffer.BlockCopy(b, 0, buf, at, 4);
    }

    // Inbound on the real interface the query left from — mirrors how NatRedirectMiddleware's
    // reply leg delivers (Outbound=false, Loopback=false, original IfIdx).
    private static WinDivertAddress BuildInboundAddress(uint ifIdx, uint subIfIdx)
    {
        WinDivertAddress addr = default;
        addr.Layer = WinDivertLayer.Network;
        addr.Outbound = false;
        addr.Loopback = false;
        addr.IPv6 = false;
        addr.Network.IfIdx = ifIdx;
        addr.Network.SubIfIdx = subIfIdx;
        return addr;
    }
}
