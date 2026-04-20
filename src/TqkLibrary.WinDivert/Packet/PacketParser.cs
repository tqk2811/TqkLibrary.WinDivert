namespace TqkLibrary.WinDivert.Packet;

public static class PacketParser
{
    public static ParsedPacket? TryParse(byte[] buffer, int length)
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
            return new ParsedPacket(buffer, length, isIpv6: false, protocol: proto, ipOffset: 0, ipHeaderLength: ihl);
        }
        if (version == 6)
        {
            if (length < 40) return null;
            byte next = buffer[6];
            // Does not walk extension headers; assumes next-header is the transport protocol.
            return new ParsedPacket(buffer, length, isIpv6: true, protocol: (IpProtocol)next, ipOffset: 0, ipHeaderLength: 40);
        }
        return null;
    }
}
