using System;
using System.Net;
using TqkLibrary.WinDivert.Packet.Models;

namespace TqkLibrary.WinDivert.Packet;

/// <summary>
/// Builds the TCP reset that ends a connection from the point of view of the process that just
/// sent a packet on it — the reply the peer would send if it had forgotten the connection.
/// </summary>
/// <remarks>
/// Given a packet the process sent, the reset travels the other way: addresses and ports swapped,
/// and its sequence number set to the acknowledgment number the process just sent, which is
/// exactly the next byte the process expects from the peer. A reset carrying that number is the
/// one a TCP stack accepts on the spot; RFC 5961 §3.2 answers any other in-window value with a
/// challenge ACK and keeps the connection. Checksums are left at zero: the injector is where the
/// driver computes them for every packet it sends, this one included.
///
/// A packet without the ACK flag — a bare SYN — carries no acknowledgment number, and the reset
/// built from it has sequence number zero. Such a flow has not escaped anything: it is being
/// captured from that very SYN, so nothing builds a reset for it.
/// </remarks>
public sealed class TcpResetPacketBuilder
{
    private const int TcpHeaderLength = 20;
    private const int Ipv4HeaderLength = 20;
    private const int Ipv6HeaderLength = 40;
    private const byte TcpProtocol = 6;
    private const byte HopLimit = 64;

    private const byte FlagFin = 0x01;
    private const byte FlagSyn = 0x02;
    private const byte FlagRst = 0x04;
    private const byte FlagAck = 0x10;

    /// <summary>
    /// The reset to inject INBOUND to the process, built from a packet the process sent.
    /// </summary>
    public byte[] BuildResetTowardsSender(ParsedPacket packet)
    {
        if (packet is null) throw new ArgumentNullException(nameof(packet));
        if (!packet.IsTcp) throw new ArgumentException("A TCP packet is required", nameof(packet));

        TcpHeaderView tcp = packet.Tcp;
        int ipHeaderLength = packet.IsIpv6 ? Ipv6HeaderLength : Ipv4HeaderLength;
        byte[] buffer = new byte[ipHeaderLength + TcpHeaderLength];

        // From the peer, to the process.
        if (packet.IsIpv6) WriteIpv6Header(buffer, source: packet.Destination, destination: packet.Source);
        else WriteIpv4Header(buffer, source: packet.Destination, destination: packet.Source);

        // What the peer would acknowledge: everything the process has sent so far, a SYN or a FIN
        // each taking one byte of sequence space.
        uint acknowledges = tcp.SequenceNumber
            + (uint)packet.PayloadLength
            + (uint)((tcp.Flags & FlagSyn) != 0 ? 1 : 0)
            + (uint)((tcp.Flags & FlagFin) != 0 ? 1 : 0);

        int t = ipHeaderLength;
        WriteUInt16(buffer, t + 0, packet.DestinationPort);
        WriteUInt16(buffer, t + 2, packet.SourcePort);
        WriteUInt32(buffer, t + 4, tcp.AcknowledgmentNumber);   // sequence = the byte it expects next
        WriteUInt32(buffer, t + 8, acknowledges);
        buffer[t + 12] = (byte)((TcpHeaderLength / 4) << 4);    // data offset, no options
        buffer[t + 13] = FlagRst | FlagAck;
        // window [14..15] = 0, checksum [16..17] = 0 (the injector fills it), urgent [18..19] = 0
        return buffer;
    }

    private static void WriteIpv4Header(byte[] buffer, IPAddress source, IPAddress destination)
    {
        buffer[0] = 0x45;                                   // version 4, IHL 5
        WriteUInt16(buffer, 2, (ushort)buffer.Length);      // total length
        // [4..7] identification, flags, fragment offset = 0
        buffer[8] = HopLimit;                               // TTL
        buffer[9] = TcpProtocol;
        // [10..11] header checksum = 0 (the injector fills it)
        WriteAddress(buffer, 12, source, 4);
        WriteAddress(buffer, 16, destination, 4);
    }

    private static void WriteIpv6Header(byte[] buffer, IPAddress source, IPAddress destination)
    {
        buffer[0] = 0x60;                                   // version 6, traffic class / flow label 0
        WriteUInt16(buffer, 4, TcpHeaderLength);            // payload length
        buffer[6] = TcpProtocol;                            // next header
        buffer[7] = HopLimit;
        WriteAddress(buffer, 8, source, 16);
        WriteAddress(buffer, 24, destination, 16);
    }

    private static void WriteAddress(byte[] buffer, int at, IPAddress address, int expectedLength)
    {
        byte[] bytes = address.GetAddressBytes();
        if (bytes.Length != expectedLength)
            throw new ArgumentException($"An address of {expectedLength} bytes is required", nameof(address));
        Buffer.BlockCopy(bytes, 0, buffer, at, expectedLength);
    }

    private static void WriteUInt16(byte[] buffer, int at, ushort value)
    {
        buffer[at] = (byte)(value >> 8);
        buffer[at + 1] = (byte)value;
    }

    private static void WriteUInt32(byte[] buffer, int at, uint value)
    {
        buffer[at] = (byte)(value >> 24);
        buffer[at + 1] = (byte)(value >> 16);
        buffer[at + 2] = (byte)(value >> 8);
        buffer[at + 3] = (byte)value;
    }
}
