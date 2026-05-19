using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.WinDivert.Flow;
using TqkLibrary.WinDivert.Native;

namespace TqkLibrary.WinDivert.Redirect;

// PacketInterceptor only sees IPv4 (`ip and ...` filter), so any IPv6 traffic of the target
// would otherwise be emitted by the kernel direct — leaking the real client IPv6 address.
// This blocker opens a parallel NETWORK-layer handle filtered to IPv6 TCP/UDP, drops packets
// belonging to the target process (cross-referenced via SocketTracker), and re-injects
// everything else so other processes keep working.
//
// Parsing is intentionally minimal: no IPv6 extension headers are walked. Almost all user-
// mode application traffic uses NextHeader=TCP(6) / UDP(17) directly; if extension headers
// are present, we conservatively pass the packet through (rather than mis-parsing and
// blocking unrelated traffic).
public sealed class Ipv6Blocker : IDisposable
{
    private readonly SocketTracker _tracker;
    private readonly CancellationTokenSource _cts = new();
    private Task? _pumpTask;
    private WinDivertHandle? _handle;

    public Ipv6Blocker(SocketTracker tracker)
    {
        _tracker = tracker ?? throw new ArgumentNullException(nameof(tracker));
    }

    public void Start(short priority)
    {
        string filter = "ipv6 and (tcp or udp) and not impostor";
        DiagnosticLogger.Log("V6X", $"Open filter=\"{filter}\" priority={priority}");
        _handle = WinDivertHandle.Open(filter, WinDivertLayer.Network, priority, WinDivertOpenFlags.None);
        _pumpTask = Task.Run(() => PumpLoop(_cts.Token));
    }

    private void PumpLoop(CancellationToken ct)
    {
        byte[] buffer = new byte[65535];
        while (!ct.IsCancellationRequested)
        {
            if (_handle == null) return;
            if (!_handle.TryRecv(buffer, out int length, out WinDivertAddress addr))
                break;

            bool drop;
            try
            {
                drop = ShouldDrop(buffer, length, ref addr);
            }
            catch (Exception ex)
            {
                DiagnosticLogger.Log("V6X", $"ShouldDrop threw, passing through: {ex.GetType().Name}: {ex.Message}");
                drop = false;
            }

            if (drop) continue;
            _handle.TrySend(buffer, length, ref addr);
        }
    }

    // Returns true if the packet belongs to the tracked process and should be dropped.
    // Returns false for non-target traffic or for packets we cannot confidently parse.
    private bool ShouldDrop(byte[] buffer, int length, ref WinDivertAddress addr)
    {
        // Minimum IPv6 (40) + TCP/UDP port pair (4).
        if (length < 44) return false;
        if ((buffer[0] >> 4) != 6) return false;

        byte nextHeader = buffer[6];
        if (nextHeader != 6 && nextHeader != 17) return false;

        byte[] srcBytes = new byte[16];
        byte[] dstBytes = new byte[16];
        Buffer.BlockCopy(buffer, 8, srcBytes, 0, 16);
        Buffer.BlockCopy(buffer, 24, dstBytes, 0, 16);
        IPAddress srcIp = new IPAddress(srcBytes);
        IPAddress dstIp = new IPAddress(dstBytes);

        ushort srcPort = (ushort)((buffer[40] << 8) | buffer[41]);
        ushort dstPort = (ushort)((buffer[42] << 8) | buffer[43]);

        // Localise to the target's perspective: the tracker's keys store (local, remote)
        // where "local" is the target side. Outbound packets put the target as source;
        // inbound packets put the target as destination.
        IPAddress localIp;
        ushort localPort;
        IPAddress remoteIp;
        ushort remotePort;
        if (addr.Outbound)
        {
            localIp = srcIp; localPort = srcPort;
            remoteIp = dstIp; remotePort = dstPort;
        }
        else
        {
            localIp = dstIp; localPort = dstPort;
            remoteIp = srcIp; remotePort = srcPort;
        }

        bool target = nextHeader == 6
            ? _tracker.IsTrackedTcp(new FlowKey(6, localIp, localPort, remoteIp, remotePort))
            : _tracker.IsTrackedUdp(localIp, localPort);

        if (target)
        {
            DiagnosticLogger.Log("V6X",
                $"DROP {(addr.Outbound ? "out" : "in")} {(nextHeader == 6 ? "tcp" : "udp")} {srcIp}:{srcPort} -> {dstIp}:{dstPort} len={length}");
        }
        return target;
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
