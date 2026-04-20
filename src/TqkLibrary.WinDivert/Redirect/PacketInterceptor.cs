using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.WinDivert.Flow;
using TqkLibrary.WinDivert.Native;
using TqkLibrary.WinDivert.Packet;

namespace TqkLibrary.WinDivert.Redirect;

// Core NAT logic on the NETWORK layer. Captures both the egress path from the target process
// (to rewrite destination onto the relay) and the loopback reply path from the relay (to
// rewrite the source back to the original destination).
//
// Outbound (target-process -> real destination):
//   (srcA:sp, dstB:bp) -> (srcLoopback:sp, dstLoopback:relayPort)
//   NAT stores: srcPort sp -> { origSrcIp=A, origDst=B:bp, pid }
//
// Inbound on loopback (relay -> target-process):
//   (srcLoopback:relayPort, dstLoopback:sp) -> (srcB:bp, dstA:sp)
//   Looked up by dstPort=sp.
public sealed class PacketInterceptor : IDisposable
{
    private readonly SocketTracker _socketTracker;
    private readonly NatTable _nat;
    private readonly uint _pid;
    private readonly int _tcpRelayPort;
    private readonly int _udpRelayPort;
    private readonly RedirectProtocol _protocols;

    private readonly CancellationTokenSource _cts = new();
    private Task? _pumpTask;
    private WinDivertHandle? _handle;

    public PacketInterceptor(
        SocketTracker socketTracker,
        NatTable nat,
        uint processId,
        int tcpRelayPort,
        int udpRelayPort,
        RedirectProtocol protocols)
    {
        _socketTracker = socketTracker;
        _nat = nat;
        _pid = processId;
        _tcpRelayPort = tcpRelayPort;
        _udpRelayPort = udpRelayPort;
        _protocols = protocols;
    }

    public void Start(short priority)
    {
        // IPv4 only in this scaffold; extending to IPv6 means duplicating the filter or using
        // ipv6 packet branch in the parser — the NAT logic itself is address-family-agnostic.
        string proto = BuildProtoFilter();
        string filter = $"ip and ({proto})";
        _handle = WinDivertHandle.Open(
            filter,
            WinDivertLayer.Network,
            priority: priority,
            flags: WinDivertOpenFlags.None);
        _pumpTask = Task.Run(() => PumpLoop(_cts.Token));
    }

    private string BuildProtoFilter()
    {
        if (_protocols == RedirectProtocol.All) return "tcp or udp";
        if (_protocols == RedirectProtocol.Tcp) return "tcp";
        if (_protocols == RedirectProtocol.Udp) return "udp";
        return "false";
    }

    private void PumpLoop(CancellationToken ct)
    {
        byte[] buffer = new byte[65535];
        while (!ct.IsCancellationRequested)
        {
            if (_handle == null) return;
            if (!_handle.TryRecv(buffer, out int length, out WinDivertAddress addr))
                break;

            bool modified = false;
            try
            {
                modified = Process(buffer, length, ref addr);
            }
            catch
            {
                // fall through: reinject unchanged
            }

            if (modified)
                _handle.CalcChecksums(buffer, length, ref addr);

            _handle.TrySend(buffer, length, ref addr);
        }
    }

    private bool Process(byte[] buffer, int length, ref WinDivertAddress addr)
    {
        ParsedPacket? p = PacketParser.TryParse(buffer, length);
        if (p == null) return false;
        if (!(p.IsTcp || p.IsUdp)) return false;

        byte proto = (byte)p.Protocol;
        bool isTcp = p.IsTcp;

        if (addr.Outbound)
        {
            // Egress from target process (before rewrite, src is still process's real addr).
            IPAddress srcIp = p.Source;
            ushort srcPort = p.SourcePort;
            IPAddress dstIp = p.Destination;
            ushort dstPort = p.DestinationPort;

            bool tracked = isTcp
                ? _socketTracker.IsTrackedTcp(new FlowKey(proto, srcIp, srcPort, dstIp, dstPort))
                : _socketTracker.IsTrackedUdp(srcIp, srcPort);

            if (!tracked) return false;

            // Record/refresh NAT entry (keyed by srcPort).
            var entry = new NatEntry(_pid, proto, srcIp, srcPort, dstIp, dstPort);
            _nat.Upsert(entry);

            int relayPort = isTcp ? _tcpRelayPort : _udpRelayPort;
            IPAddress loopback = p.IsIpv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback;

            p.SetSource(loopback, srcPort);
            p.SetDestination(loopback, (ushort)relayPort);
            return true;
        }
        else
        {
            // Ingress side. We only care about the reply leg coming back from the relay on loopback:
            // (src=loopback:relayPort, dst=loopback:sp). Everything else is left alone.
            ushort srcPort = p.SourcePort;
            ushort dstPort = p.DestinationPort;

            int expectedRelay = isTcp ? _tcpRelayPort : _udpRelayPort;
            if (srcPort != expectedRelay) return false;

            NatEntry? entry = _nat.Find(proto, dstPort);
            if (entry == null) return false;

            // Rewrite so the target process sees packets as if from the original destination.
            p.SetSource(entry.OriginalDestinationAddress, entry.OriginalDestinationPort);
            p.SetDestination(entry.OriginalSourceAddress, entry.OriginalSourcePort);
            return true;
        }
    }

    public void Dispose()
    {
        try { _cts.Cancel(); } catch { }
        try { _handle?.Shutdown(); } catch { }
        try { _pumpTask?.Wait(TimeSpan.FromSeconds(1)); } catch { }
        _handle?.Dispose();
        _cts.Dispose();
    }
}
