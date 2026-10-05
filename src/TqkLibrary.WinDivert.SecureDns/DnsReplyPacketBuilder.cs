using System;
using System.Net;
using System.Net.Sockets;

namespace TqkLibrary.WinDivert.SecureDns;

/// <summary>
/// Builds the inbound UDP datagram that delivers a DNS answer FROM the server the client asked
/// (source port 53) TO the client's ephemeral port, over IPv4 or IPv6 to match the query.
/// </summary>
/// <remarks>
/// The injector recomputes every checksum before sending, so the IPv4 checksums are left zero.
/// The IPv6 UDP checksum is filled in anyway: unlike IPv4 it is mandatory there (RFC 8200 §8.1),
/// and a datagram that is valid on its own does not depend on the injector to be deliverable.
/// </remarks>
public sealed class DnsReplyPacketBuilder
{
    private const ushort DnsPort = 53;
    private const int Ipv4HeaderLength = 20;
    private const int Ipv6HeaderLength = 40;
    private const int UdpHeaderLength = 8;
    private const byte UdpProtocol = 17;
    private const byte HopLimit = 64;

    /// <summary>
    /// Returns the reply datagram. <paramref name="serverIp"/> and <paramref name="clientIp"/>
    /// must be of the same family; that family decides the IP version of the packet.
    /// </summary>
    public byte[] Build(IPAddress serverIp, IPAddress clientIp, ushort clientPort, byte[] responseWire)
    {
        if (serverIp is null) throw new ArgumentNullException(nameof(serverIp));
        if (clientIp is null) throw new ArgumentNullException(nameof(clientIp));
        if (responseWire is null) throw new ArgumentNullException(nameof(responseWire));
        if (serverIp.AddressFamily != clientIp.AddressFamily)
            throw new ArgumentException("server and client addresses must be of the same family", nameof(clientIp));

        return serverIp.AddressFamily == AddressFamily.InterNetworkV6
            ? BuildIpv6(serverIp, clientIp, clientPort, responseWire)
            : BuildIpv4(serverIp, clientIp, clientPort, responseWire);
    }

    private static byte[] BuildIpv4(IPAddress serverIp, IPAddress clientIp, ushort clientPort, byte[] responseWire)
    {
        int total = Ipv4HeaderLength + UdpHeaderLength + responseWire.Length;
        byte[] buf = new byte[total];

        buf[0] = 0x45;                 // version 4, IHL 5 (no options)
        buf[1] = 0x00;                 // DSCP/ECN
        buf[2] = (byte)(total >> 8);   // Total Length
        buf[3] = (byte)total;
        // [4..7] identification + flags/fragment = 0
        buf[8] = HopLimit;             // TTL
        buf[9] = UdpProtocol;
        // [10..11] header checksum = 0 (the injector fills it)
        WriteAddress(buf, 12, serverIp, 4);  // source = DNS server
        WriteAddress(buf, 16, clientIp, 4);  // destination = client

        // UDP checksum = 0 here, which IPv4 allows; the injector fills it anyway.
        WriteUdp(buf, Ipv4HeaderLength, clientPort, responseWire);
        return buf;
    }

    private static byte[] BuildIpv6(IPAddress serverIp, IPAddress clientIp, ushort clientPort, byte[] responseWire)
    {
        int udpLen = UdpHeaderLength + responseWire.Length;
        byte[] buf = new byte[Ipv6HeaderLength + udpLen];

        buf[0] = 0x60;                 // version 6, traffic class + flow label = 0
        buf[4] = (byte)(udpLen >> 8);  // Payload Length (everything after the fixed header)
        buf[5] = (byte)udpLen;
        buf[6] = UdpProtocol;          // Next Header
        buf[7] = HopLimit;
        WriteAddress(buf, 8, serverIp, 16);   // source = DNS server
        WriteAddress(buf, 24, clientIp, 16);  // destination = client

        WriteUdp(buf, Ipv6HeaderLength, clientPort, responseWire);

        ushort checksum = Ipv6UdpChecksum(buf, Ipv6HeaderLength, udpLen);
        buf[Ipv6HeaderLength + 6] = (byte)(checksum >> 8);
        buf[Ipv6HeaderLength + 7] = (byte)checksum;
        return buf;
    }

    private static void WriteUdp(byte[] buf, int udp, ushort clientPort, byte[] responseWire)
    {
        int udpLen = UdpHeaderLength + responseWire.Length;
        buf[udp + 0] = (byte)(DnsPort >> 8);     // source port = 53
        buf[udp + 1] = (byte)DnsPort;
        buf[udp + 2] = (byte)(clientPort >> 8);  // destination port = client ephemeral
        buf[udp + 3] = (byte)clientPort;
        buf[udp + 4] = (byte)(udpLen >> 8);      // UDP Length
        buf[udp + 5] = (byte)udpLen;
        // [udp+6..7] checksum, see the callers
        Buffer.BlockCopy(responseWire, 0, buf, udp + UdpHeaderLength, responseWire.Length);
    }

    private static void WriteAddress(byte[] buf, int at, IPAddress ip, int size)
    {
        byte[] b = ip.GetAddressBytes();
        if (b.Length != size) throw new ArgumentException($"{size * 8}-bit address required", nameof(ip));
        Buffer.BlockCopy(b, 0, buf, at, size);
    }

    // One's-complement sum over the IPv6 pseudo-header (source, destination, upper-layer length,
    // next header) and the UDP header + payload, with the checksum field taken as zero. A result
    // of zero is sent as 0xFFFF: zero means "no checksum", which IPv6 forbids.
    private static ushort Ipv6UdpChecksum(byte[] packet, int udpOffset, int udpLen)
    {
        ulong sum = 0;
        sum += SumWords(packet, 8, 32);           // source + destination addresses
        sum += (uint)udpLen;                      // upper-layer packet length
        sum += UdpProtocol;                       // next header
        sum += SumWords(packet, udpOffset, udpLen);

        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        ushort result = (ushort)~sum;
        return result == 0 ? (ushort)0xFFFF : result;
    }

    private static ulong SumWords(byte[] b, int offset, int length)
    {
        ulong sum = 0;
        int end = offset + length;
        int i = offset;
        for (; i + 1 < end; i += 2) sum += (uint)((b[i] << 8) | b[i + 1]);
        if (i < end) sum += (uint)(b[i] << 8);  // odd trailing byte, padded with zero
        return sum;
    }
}
