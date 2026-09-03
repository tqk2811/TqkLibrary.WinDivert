using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace TqkLibrary.WinDivert.Redirect;

// For UDP, the relay listens on 127.0.0.1:<ephemeral> and — when IPv6 redirect is enabled — on
// [::1]:<ephemeral> too. Each incoming datagram from the target process (after rewrite) carries
// the original source port as its UDP source. We maintain one upstream socket per distinct
// (origSrcPort, family) so reply packets from the real destination can be routed back; the packet
// interceptor rewrites their headers so the target process sees them coming from the original
// destination.
public sealed class UdpRelayServer : IDisposable
{
    private readonly NatTable _nat;
    private readonly UdpDatagramHandler? _handler;
    private readonly UdpClient _listener;
    private readonly UdpClient? _listenerV6;
    private readonly CancellationTokenSource _cts = new();
    private readonly List<Task> _recvLoops = new();
    private readonly ConcurrentDictionary<int, UdpUpstream> _upstreams = new();

    /// <summary>Loopback port the IPv4 relay listens on.</summary>
    public int Port { get; }

    /// <summary>Loopback port the IPv6 relay listens on; 0 when IPv6 redirect is off.</summary>
    public int PortV6 { get; }

    public UdpRelayServer(NatTable nat, UdpDatagramHandler? handler, bool enableIpv6 = false)
    {
        _nat = nat;
        _handler = handler;
        _listener = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        Port = ((IPEndPoint)_listener.Client.LocalEndPoint!).Port;
        if (enableIpv6 && Socket.OSSupportsIPv6)
        {
            // Same as the TCP relay: a refused ::1 bind means "no IPv6 relay", not a dead start.
            try
            {
                _listenerV6 = new UdpClient(new IPEndPoint(IPAddress.IPv6Loopback, 0));
                PortV6 = ((IPEndPoint)_listenerV6.Client.LocalEndPoint!).Port;
            }
            catch (SocketException)
            {
                _listenerV6 = null;
                PortV6 = 0;
            }
        }
    }

    public void Start()
    {
        _recvLoops.Add(Task.Run(() => ReceiveLoop(_listener, isIpv6: false, _cts.Token)));
        if (_listenerV6 != null)
            _recvLoops.Add(Task.Run(() => ReceiveLoop(_listenerV6, isIpv6: true, _cts.Token)));
    }

    private async Task ReceiveLoop(UdpClient listener, bool isIpv6, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            UdpReceiveResult result;
            try
            {
                result = await listener.ReceiveAsync().ConfigureAwait(false);
            }
            catch (ObjectDisposedException) { return; }
            catch (SocketException) { return; }

            ushort srcPort = (ushort)result.RemoteEndPoint.Port;
            NatEntry? entry = _nat.Find(protocol: 17, srcPort: srcPort, isIpv6: isIpv6);
            if (entry == null) continue;

            byte[] payload = result.Buffer;
            if (_handler != null)
            {
                var dg = new RedirectedUdpDatagram(
                    entry.ProcessId,
                    new IPEndPoint(entry.OriginalSourceAddress, entry.OriginalSourcePort),
                    entry.OriginalDestination,
                    payload);
                byte[]? maybe = _handler(dg, ct);
                if (maybe == null) continue;
                payload = maybe;
            }

            var up = _upstreams.GetOrAdd(UpstreamKey(srcPort, isIpv6), _ => new UdpUpstream(entry.OriginalDestination));
            try
            {
                await up.SendAsync(payload, ct).ConfigureAwait(false);
            }
            catch { /* swallow; reply pump dies when socket closes */ }
        }
    }

    // One upstream socket per (source port, family). The two families have independent port
    // spaces, so the family bit is what keeps an IPv4 flow from stealing an IPv6 flow's socket.
    // Packed into an int rather than a tuple because this library also targets .NET Framework 4.6.2,
    // where System.ValueTuple is not available.
    private static int UpstreamKey(ushort srcPort, bool isIpv6) => srcPort | (isIpv6 ? 1 << 16 : 0);

    // Send a UDP payload to the target process as if it originated from the original destination.
    // The packet is emitted FROM the relay listener (so its source = the relay port the
    // PacketInterceptor recognises in case-2), TO the loopback address of the right family at
    // <originalClientPort>. The interceptor then rewrites src=relay->origDst and dst=loopback->origSrc
    // and reinjects on the real interface.
    public Task InjectReplyToProcessAsync(ushort processClientPort, byte[] payload, bool isIpv6 = false)
    {
        if (payload is null) throw new ArgumentNullException(nameof(payload));
        if (isIpv6)
        {
            if (_listenerV6 == null) throw new InvalidOperationException("IPv6 UDP redirect is not enabled");
            return _listenerV6.SendAsync(payload, payload.Length, new IPEndPoint(IPAddress.IPv6Loopback, processClientPort));
        }
        return _listener.SendAsync(payload, payload.Length, new IPEndPoint(IPAddress.Loopback, processClientPort));
    }

    public void Dispose()
    {
        try { _cts.Cancel(); } catch { }
        try { _listener.Close(); } catch { }
        try { _listenerV6?.Close(); } catch { }
        foreach (var kv in _upstreams) kv.Value.Dispose();
        _upstreams.Clear();
        try { Task.WaitAll(_recvLoops.ToArray(), TimeSpan.FromSeconds(1)); } catch { }
        _cts.Dispose();
    }

    private sealed class UdpUpstream : IDisposable
    {
        private readonly UdpClient _socket;
        private readonly IPEndPoint _remote;

        public UdpUpstream(IPEndPoint remote)
        {
            // The parameterless UdpClient ctor is IPv4-only, so the family has to follow the
            // destination or every IPv6 datagram would fail to send.
            _socket = new UdpClient(remote.AddressFamily);
            _remote = remote;
        }

        public async Task SendAsync(byte[] payload, CancellationToken ct)
        {
            await _socket.SendAsync(payload, payload.Length, _remote).ConfigureAwait(false);
            // Reply leg for UDP would require correlating back via WinDivert on loopback —
            // handled by PacketInterceptor when a reply arrives; we only own the egress leg here.
        }

        public void Dispose()
        {
            try { _socket.Close(); } catch { }
        }
    }
}
