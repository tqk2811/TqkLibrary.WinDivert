using System;
using System.Net;

namespace TqkLibrary.WinDivert.Packet;

public enum IpProtocol : byte
{
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
    IcmpV6 = 58,
}

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
