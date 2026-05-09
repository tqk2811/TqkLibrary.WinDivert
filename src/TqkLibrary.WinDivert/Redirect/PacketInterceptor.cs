using System;
using System.Net;
using System.Runtime.InteropServices;
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
        // `not impostor` avoids re-capturing packets we reinjected ourselves (prevents loops).
        string proto = BuildProtoFilter();
        string filter = $"ip and ({proto}) and not impostor";
        DiagnosticLogger.Log("INT", $"Open filter=\"{filter}\" priority={priority} tcpRelay={_tcpRelayPort} udpRelay={_udpRelayPort} pid={_pid}");
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

    private enum ProcessResult { Pass, Modified, Drop }

    private void PumpLoop(CancellationToken ct)
    {
        byte[] buffer = new byte[65535];
        while (!ct.IsCancellationRequested)
        {
            if (_handle == null) return;
            if (!_handle.TryRecv(buffer, out int length, out WinDivertAddress addr))
                break;

            ProcessResult result;
            try
            {
                result = Process(buffer, length, ref addr);
            }
            catch (Exception ex)
            {
                DiagnosticLogger.Log("INT", $"Process threw: {ex.GetType().Name}: {ex.Message}");
                result = ProcessResult.Pass;
            }

            if (result == ProcessResult.Drop)
                continue;

            if (result == ProcessResult.Modified)
                _handle.CalcChecksums(buffer, length, ref addr);

            bool sent = _handle.TrySend(buffer, length, ref addr);
            if (result == ProcessResult.Modified && !sent)
                DiagnosticLogger.Log("INT", $"  TrySend FAILED win32={Marshal.GetLastWin32Error()}");
        }
    }

    private static string TcpFlags(ParsedPacket p)
    {
        if (!p.IsTcp) return "";
        var t = p.Tcp;
        var sb = new System.Text.StringBuilder(8);
        if (t.Syn) sb.Append('S');
        if (t.Ack) sb.Append('A');
        if (t.Fin) sb.Append('F');
        if (t.Rst) sb.Append('R');
        return sb.Length == 0 ? "-" : sb.ToString();
    }

    private string Describe(ParsedPacket p, in WinDivertAddress addr, int length)
    {
        string proto = p.IsTcp ? "tcp" : p.IsUdp ? "udp" : ((byte)p.Protocol).ToString();
        string flags = p.IsTcp ? $" flags={TcpFlags(p)}" : "";
        return $"out={(addr.Outbound ? 1 : 0)} lb={(addr.Loopback ? 1 : 0)} if={addr.Network.IfIdx}/{addr.Network.SubIfIdx} {proto} {p.Source}:{p.SourcePort} -> {p.Destination}:{p.DestinationPort} len={length}{flags}";
    }

    private ProcessResult Process(byte[] buffer, int length, ref WinDivertAddress addr)
    {
        ParsedPacket? p = PacketParser.TryParse(buffer, length);
        if (p == null) return ProcessResult.Pass;
        if (!(p.IsTcp || p.IsUdp)) return ProcessResult.Pass;

        byte proto = (byte)p.Protocol;
        bool isTcp = p.IsTcp;
        int expectedRelay = isTcp ? _tcpRelayPort : _udpRelayPort;

        DiagnosticLogger.Log("INT", $"recv {Describe(p, addr, length)}");

        // Case 1: egress from target process on a real interface → redirect to local relay.
        if (addr.Outbound && !addr.Loopback)
        {
            IPAddress srcIp = p.Source;
            ushort srcPort = p.SourcePort;
            IPAddress dstIp = p.Destination;
            ushort dstPort = p.DestinationPort;

            bool tracked = isTcp
                ? _socketTracker.IsTrackedTcp(new FlowKey(proto, srcIp, srcPort, dstIp, dstPort))
                : _socketTracker.IsTrackedUdp(srcIp, srcPort);

            DiagnosticLogger.Log("INT", $"  egress tracked={tracked} tcpFlows={_socketTracker.TcpSnapshot.Count} natCount={_nat.Count}");
            if (!tracked) return ProcessResult.Pass;

            // Store the real-interface IfIdx so the reply path can reinject on the same interface.
            var entry = new NatEntry(_pid, proto, srcIp, srcPort, dstIp, dstPort, addr.Network.IfIdx, addr.Network.SubIfIdx);
            _nat.Upsert(entry);
            DiagnosticLogger.Log("INT", $"  nat.upsert {(isTcp ? "tcp" : "udp")} srcPort={srcPort} -> origDst={dstIp}:{dstPort} ifIdx={addr.Network.IfIdx}");

            IPAddress loopback = p.IsIpv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback;
            p.SetSource(loopback, srcPort);
            p.SetDestination(loopback, (ushort)expectedRelay);

            // Re-inject at the WFP OUTBOUND hook on the loopback interface. The kernel handles
            // both halves of the loopback transmission and delivers the SYN to the relay's listener.
            // Switching to Outbound=false here causes WFP to silently drop the packet (no listener match).
            addr.Loopback = true;
            addr.Network.IfIdx = 1;
            addr.Network.SubIfIdx = 0;
            DiagnosticLogger.Log("INT", $"  -> REDIRECT 127.0.0.1:{srcPort} -> 127.0.0.1:{expectedRelay} (Outbound=true Loopback=true IfIdx=1)");
            return ProcessResult.Modified;
        }

        // Case 2: relay listener's reply on loopback (src=loopback:relayPort, dst=loopback:origSrcPort).
        if (addr.Loopback && p.SourcePort == expectedRelay)
        {
            ushort dstPort = p.DestinationPort;
            NatEntry? entry = _nat.Find(proto, dstPort);
            DiagnosticLogger.Log("INT", $"  reply candidate dstPort={dstPort} natHit={(entry != null)} addr.Outbound={addr.Outbound}");
            if (entry == null) return ProcessResult.Pass;

            // Loopback packets are captured twice (sender outbound + receiver inbound). Handle on
            // the outbound capture; the inbound duplicate would otherwise hit a nonexistent socket
            // and produce a spurious RST, so drop it.
            if (!addr.Outbound)
            {
                DiagnosticLogger.Log("INT", "  -> DROP loopback inbound duplicate");
                return ProcessResult.Drop;
            }

            p.SetSource(entry.OriginalDestinationAddress, entry.OriginalDestinationPort);
            p.SetDestination(entry.OriginalSourceAddress, entry.OriginalSourcePort);

            // Reinject as inbound on the real interface the original socket lives on.
            addr.Loopback = false;
            addr.Outbound = false;
            addr.Network.IfIdx = entry.IfIdx;
            addr.Network.SubIfIdx = entry.SubIfIdx;
            DiagnosticLogger.Log("INT", $"  -> REPLY rewrite to {entry.OriginalDestinationAddress}:{entry.OriginalDestinationPort} -> {entry.OriginalSourceAddress}:{entry.OriginalSourcePort} ifIdx={entry.IfIdx}");
            return ProcessResult.Modified;
        }

        return ProcessResult.Pass;
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
