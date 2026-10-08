using System;
using System.Buffers.Binary;
using System.Net;

namespace TqkLibrary.WinDivert.Redirect;

/// <summary>
/// The redirect pipeline's fast path: an outbound packet of a flow no tracked process owns is
/// released by the pump straight off the raw buffer, without being parsed or run through the
/// stages — none of them would touch it.
/// </summary>
/// <remarks>
/// Only valid for a pipeline made of the built-in stages, each of which was checked to pass such a
/// packet untouched:
///   * DnsAnswerSniffMiddleware reads UDP from source port 53 only;
///   * DnsOverHttpsMiddleware claims outbound UDP to port 53 only;
///   * NatRedirectMiddleware rewrites tracked egress and relay replies on loopback, holds untracked
///     SYNs, and passes any other untracked egress after asking for a background reconcile —
///     which this class asks for too, so a flow the sweep finds is still captured from its next
///     packet;
///   * BlockTargetUdpMiddleware drops tracked UDP only.
/// A caller-supplied stage (RedirectOptions.ConfigureNetworkPipeline) could want anything, so the
/// redirector installs no bypass then. Port 53 is excluded in both directions and on TCP too,
/// which is wider than the DNS stages need — the cheap side to err on.
/// <para>
/// Everything uncertain is false: loopback, inbound, SYN, fragments, IPv6 extension headers,
/// anything truncated. The tracker lookups still allocate two <see cref="IPAddress"/> objects
/// (its keys are built on them); that is all that is left of the per-packet cost.
/// </para>
/// </remarks>
public sealed class UntrackedEgressBypass : IPacketBypass
{
    private const int ProtocolTcp = 6;
    private const int ProtocolUdp = 17;
    private const ushort DnsPort = 53;

    private readonly ISocketTracker _tracker;
    private readonly RelayPorts _relayPorts;
    private readonly RedirectProtocol _protocols;

    /// <param name="relayPorts">The same relay ports the pipeline's NAT stage was given.</param>
    /// <param name="protocols">The same protocol set the pipeline's NAT stage was given.</param>
    public UntrackedEgressBypass(ISocketTracker tracker, RelayPorts relayPorts, RedirectProtocol protocols)
    {
        _tracker = tracker ?? throw new ArgumentNullException(nameof(tracker));
        _relayPorts = relayPorts;
        _protocols = protocols;
    }

    public bool ShouldRelease(ReadOnlySpan<byte> packet, in WinDivertAddress address)
    {
        // Relay replies live on loopback, and inbound packets include DNS answers the sniffer reads.
        if (!address.Outbound || address.Loopback) return false;
        if (packet.Length < 1) return false;

        bool isIpv6;
        int protocol;
        int transportOffset;
        ReadOnlySpan<byte> src;
        ReadOnlySpan<byte> dst;
        switch (packet[0] >> 4)
        {
            case 4:
            {
                if (packet.Length < 20) return false;
                int ihl = (packet[0] & 0x0F) * 4;
                if (ihl < 20 || ihl > packet.Length) return false;
                // A fragment other than the first has no ports, and a first fragment's ports do
                // not speak for the rest: the parser handles neither, so neither is decided here.
                ushort flagsAndOffset = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(6, 2));
                if ((flagsAndOffset & 0x3FFF) != 0) return false;   // MF set or offset != 0
                isIpv6 = false;
                protocol = packet[9];
                transportOffset = ihl;
                src = packet.Slice(12, 4);
                dst = packet.Slice(16, 4);
                break;
            }
            case 6:
            {
                if (packet.Length < 40) return false;
                // Only TCP/UDP straight after the fixed header; extension headers take the normal path.
                isIpv6 = true;
                protocol = packet[6];
                transportOffset = 40;
                src = packet.Slice(8, 16);
                dst = packet.Slice(24, 16);
                break;
            }
            default:
                return false;
        }

        bool isTcp;
        if (protocol == ProtocolTcp)
        {
            // Through the flags byte.
            if (packet.Length < transportOffset + 14) return false;
            isTcp = true;
        }
        else if (protocol == ProtocolUdp)
        {
            if (packet.Length < transportOffset + 8) return false;
            isTcp = false;
        }
        else
        {
            return false;
        }

        ushort srcPort = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(transportOffset, 2));
        ushort dstPort = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(transportOffset + 2, 2));
        if (srcPort == DnsPort || dstPort == DnsPort) return false;

        if (isTcp)
        {
            // A SYN without ACK is what NAT holds for a reconcile; it never passes straight through.
            byte flags = packet[transportOffset + 13];
            bool syn = (flags & 0x02) != 0;
            bool ack = (flags & 0x10) != 0;
            if (syn && !ack) return false;
        }

        var srcIp = new IPAddress(src);
        var dstIp = new IPAddress(dst);
        if (IsTracked(isTcp, srcIp, srcPort, dstIp, dstPort)) return false;

        // NAT only gets as far as its untracked branch when it redirects this protocol and has a
        // relay for this family; mirror that, including the re-check, so the one thing it does to
        // such a packet — request a background reconcile — still happens.
        RedirectProtocol thisProto = isTcp ? RedirectProtocol.Tcp : RedirectProtocol.Udp;
        if ((_protocols & thisProto) != 0 && _relayPorts.For(isTcp, isIpv6) != 0)
        {
            _tracker.RequestReconcileFromKernel();
            if (IsTracked(isTcp, srcIp, srcPort, dstIp, dstPort)) return false;
        }
        return true;
    }

    private bool IsTracked(bool isTcp, IPAddress srcIp, ushort srcPort, IPAddress dstIp, ushort dstPort)
        => isTcp
            ? _tracker.IsTrackedTcp(new FlowKey(ProtocolTcp, srcIp, srcPort, dstIp, dstPort))
            : _tracker.IsTrackedUdp(srcIp, srcPort);
}
