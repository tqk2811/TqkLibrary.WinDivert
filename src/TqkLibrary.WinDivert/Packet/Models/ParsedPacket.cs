using System;
using System.Net;
using TqkLibrary.WinDivert.Native.Models;

namespace TqkLibrary.WinDivert.Packet.Models;

public sealed class ParsedPacket
{
    public byte[] Buffer { get; }
    public int Length { get; }
    public bool IsIpv6 { get; }
    public IpProtocol Protocol { get; }

    public int IpHeaderOffset { get; }
    public int IpHeaderLength { get; }
    public int TransportHeaderOffset => IpHeaderOffset + IpHeaderLength;

    public Ipv4HeaderView Ipv4 => new Ipv4HeaderView(Buffer, IpHeaderOffset);
    public Ipv6HeaderView Ipv6 => new Ipv6HeaderView(Buffer, IpHeaderOffset);
    public TcpHeaderView Tcp => new TcpHeaderView(Buffer, TransportHeaderOffset);
    public UdpHeaderView Udp => new UdpHeaderView(Buffer, TransportHeaderOffset);

    public bool IsTcp => Protocol == IpProtocol.Tcp;
    public bool IsUdp => Protocol == IpProtocol.Udp;

    public IPAddress Source => IsIpv6 ? Ipv6.Source : Ipv4.Source;
    public IPAddress Destination => IsIpv6 ? Ipv6.Destination : Ipv4.Destination;

    public ushort SourcePort => IsTcp ? Tcp.SourcePort : IsUdp ? Udp.SourcePort : (ushort)0;
    public ushort DestinationPort => IsTcp ? Tcp.DestinationPort : IsUdp ? Udp.DestinationPort : (ushort)0;

    public IPEndPoint SourceEndPoint => new IPEndPoint(Source, SourcePort);
    public IPEndPoint DestinationEndPoint => new IPEndPoint(Destination, DestinationPort);

    /// <summary>
    /// Bytes after the transport header — the segment's data. Zero for a bare ACK, and for a
    /// protocol this parser does not read a header for.
    /// </summary>
    public int PayloadLength
    {
        get
        {
            int transportHeaderLength = IsTcp ? Tcp.DataOffset : IsUdp ? 8 : 0;
            return Math.Max(0, Length - TransportHeaderOffset - transportHeaderLength);
        }
    }

    internal ParsedPacket(byte[] buffer, int length, bool isIpv6, IpProtocol protocol, int ipOffset, int ipHeaderLength)
    {
        Buffer = buffer;
        Length = length;
        IsIpv6 = isIpv6;
        Protocol = protocol;
        IpHeaderOffset = ipOffset;
        IpHeaderLength = ipHeaderLength;
    }

    // Byte-level writers — avoid going through view structs so the C# compiler doesn't reject
    // the mutation (properties on returned structs are rvalues).
    public void SetSource(IPAddress address, ushort port)
    {
        WriteIp(address, isDestination: false);
        WritePort(port, isDestination: false);
    }

    public void SetDestination(IPAddress address, ushort port)
    {
        WriteIp(address, isDestination: true);
        WritePort(port, isDestination: true);
    }

    /// <summary>
    /// Rewrites both endpoints and patches the IPv4 header and transport checksums incrementally
    /// (RFC 1624), so the cost does not grow with the payload. Returns false and changes nothing
    /// when that is not safe: not TCP/UDP, an IPv4 fragment, an address length that differs, a
    /// checksum WinDivert did not mark valid (offloaded or unset, so there is nothing to patch),
    /// or a UDP/IPv6 datagram without a checksum (illegal; left for a full recompute).
    /// </summary>
    public bool TryRewriteIncremental(
        ReadOnlySpan<byte> newSrcIp, ushort newSrcPort, ReadOnlySpan<byte> newDstIp, ushort newDstPort,
        in WinDivertAddress addr)
    {
        if (!(IsTcp || IsUdp)) return false;
        int ipLen = IsIpv6 ? 16 : 4;
        if (newSrcIp.Length != ipLen || newDstIp.Length != ipLen) return false;

        byte[] b = Buffer;
        int ip = IpHeaderOffset;
        int transport = TransportHeaderOffset;
        int srcAt = ip + (IsIpv6 ? 8 : 12);
        int dstAt = ip + (IsIpv6 ? 24 : 16);

        if (!IsIpv6)
        {
            if ((((b[ip + 6] << 8) | b[ip + 7]) & 0x3FFF) != 0) return false;  // MF flag or a fragment offset
            if (!addr.IPChecksum) return false;
        }
        if (IsTcp ? !addr.TCPChecksum : !addr.UDPChecksum) return false;

        int checkAt = transport + (IsTcp ? 16 : 6);
        if (checkAt + 2 > Length) return false;
        ushort oldCheck = (ushort)((b[checkAt] << 8) | b[checkAt + 1]);
        if (IsUdp && IsIpv6 && oldCheck == 0) return false;

        // Old values are read before anything is written.
        Span<byte> oldAddresses = stackalloc byte[ipLen * 2];
        Span<byte> newAddresses = stackalloc byte[ipLen * 2];
        new ReadOnlySpan<byte>(b, srcAt, ipLen).CopyTo(oldAddresses);
        new ReadOnlySpan<byte>(b, dstAt, ipLen).CopyTo(oldAddresses.Slice(ipLen));
        newSrcIp.CopyTo(newAddresses);
        newDstIp.CopyTo(newAddresses.Slice(ipLen));
        ushort oldSrcPort = (ushort)((b[transport] << 8) | b[transport + 1]);
        ushort oldDstPort = (ushort)((b[transport + 2] << 8) | b[transport + 3]);

        if (!IsIpv6)
        {
            ushort ipCheck = (ushort)((b[ip + 10] << 8) | b[ip + 11]);
            ipCheck = ChecksumUpdate.UpdateBytes(ipCheck, oldAddresses, newAddresses);
            b[ip + 10] = (byte)(ipCheck >> 8);
            b[ip + 11] = (byte)ipCheck;
        }

        // UDP over IPv4 may carry no checksum (0): it stays absent, only the fields change.
        if (!(IsUdp && oldCheck == 0))
        {
            ushort check = ChecksumUpdate.UpdateBytes(oldCheck, oldAddresses, newAddresses);
            check = ChecksumUpdate.Update16(check, oldSrcPort, newSrcPort);
            check = ChecksumUpdate.Update16(check, oldDstPort, newDstPort);
            if (IsUdp && check == 0) check = 0xFFFF;  // 0 would read as "no checksum"
            b[checkAt] = (byte)(check >> 8);
            b[checkAt + 1] = (byte)check;
        }

        newSrcIp.CopyTo(new Span<byte>(b, srcAt, ipLen));
        newDstIp.CopyTo(new Span<byte>(b, dstAt, ipLen));
        b[transport] = (byte)(newSrcPort >> 8);
        b[transport + 1] = (byte)newSrcPort;
        b[transport + 2] = (byte)(newDstPort >> 8);
        b[transport + 3] = (byte)newDstPort;
        return true;
    }

    private void WriteIp(IPAddress address, bool isDestination)
    {
        byte[] bytes = address.GetAddressBytes();
        int at;
        if (IsIpv6)
        {
            if (bytes.Length != 16) throw new ArgumentException("IPv6 address required", nameof(address));
            at = IpHeaderOffset + (isDestination ? 24 : 8);
            System.Buffer.BlockCopy(bytes, 0, Buffer, at, 16);
        }
        else
        {
            if (bytes.Length != 4) throw new ArgumentException("IPv4 address required", nameof(address));
            at = IpHeaderOffset + (isDestination ? 16 : 12);
            System.Buffer.BlockCopy(bytes, 0, Buffer, at, 4);
        }
    }

    private void WritePort(ushort port, bool isDestination)
    {
        if (!(IsTcp || IsUdp)) return;
        int at = TransportHeaderOffset + (isDestination ? 2 : 0);
        Buffer[at] = (byte)(port >> 8);
        Buffer[at + 1] = (byte)port;
    }
}
