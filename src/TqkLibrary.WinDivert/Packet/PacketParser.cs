namespace TqkLibrary.WinDivert.Packet;

/// <summary>
/// The IPv4/IPv6 parser used by the pump. Stateless and allocation-free apart from the returned
/// view, so one instance serves every pipeline.
/// </summary>
public sealed class PacketParser : IPacketParser
{
    /// <summary>Shared instance for callers outside the container.</summary>
    public static PacketParser Default { get; } = new PacketParser();

    public ParsedPacket? TryParse(byte[] buffer, int length)
    {
        if (buffer is null || length < 1) return null;

        int version = buffer[0] >> 4;
        if (version == 4)
        {
            if (length < 20) return null;
            int ihl = (buffer[0] & 0x0F) * 4;
            if (ihl < 20 || ihl > length) return null;
            byte protoByte = buffer[9];
            var proto = (IpProtocol)protoByte;
            if (!HasTransportHeader(proto, ihl, length)) return null;
            return new ParsedPacket(buffer, length, isIpv6: false, protocol: proto, ipOffset: 0, ipHeaderLength: ihl);
        }
        if (version == 6)
        {
            if (length < 40) return null;
            byte next = buffer[6];
            // Does not walk extension headers; assumes next-header is the transport protocol.
            if (!HasTransportHeader((IpProtocol)next, 40, length)) return null;
            return new ParsedPacket(buffer, length, isIpv6: true, protocol: (IpProtocol)next, ipOffset: 0, ipHeaderLength: 40);
        }
        return null;
    }

    /// <summary>
    /// Whether the fixed part of a TCP (20 B) or UDP (8 B) header fits after the IP header. The
    /// Tcp/Udp views read at that offset without checking, and the pump reuses its buffer, so a
    /// truncated packet would otherwise expose the previous packet's bytes as ports and flags.
    /// Other protocols have no header read here and always pass.
    /// </summary>
    private static bool HasTransportHeader(IpProtocol protocol, int ipHeaderLength, int length) => protocol switch
    {
        IpProtocol.Tcp => ipHeaderLength + 20 <= length,
        IpProtocol.Udp => ipHeaderLength + 8 <= length,
        _ => true,
    };
}
