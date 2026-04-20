using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace TqkLibrary.WinDivert.Redirect;

// For UDP, the relay listens on 127.0.0.1:<ephemeral>. Each incoming datagram from the
// target process (after rewrite) carries the original source port as its UDP source.
// We maintain one upstream socket per distinct (origSrcPort) so reply packets from the
// real destination can be routed back; the packet interceptor rewrites their headers so
// the target process sees them coming from the original destination.
public sealed class UdpRelayServer : IDisposable
{
    private readonly NatTable _nat;
    private readonly UdpDatagramHandler? _handler;
    private readonly UdpClient _listener;
    private readonly CancellationTokenSource _cts = new();
    private Task? _recvLoop;
    private readonly ConcurrentDictionary<ushort, UdpUpstream> _upstreams = new();

    public int Port { get; }

    public UdpRelayServer(NatTable nat, UdpDatagramHandler? handler)
    {
        _nat = nat;
        _handler = handler;
        _listener = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        Port = ((IPEndPoint)_listener.Client.LocalEndPoint!).Port;
    }

    public void Start()
    {
        _recvLoop = Task.Run(() => ReceiveLoop(_cts.Token));
    }

    private async Task ReceiveLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            UdpReceiveResult result;
            try
            {
                result = await _listener.ReceiveAsync().ConfigureAwait(false);
            }
            catch (ObjectDisposedException) { return; }
            catch (SocketException) { return; }

            ushort srcPort = (ushort)result.RemoteEndPoint.Port;
            NatEntry? entry = _nat.Find(protocol: 17, srcPort: srcPort);
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

            var up = _upstreams.GetOrAdd(srcPort, _ => new UdpUpstream(entry.OriginalDestination));
            try
            {
                await up.SendAsync(payload, ct).ConfigureAwait(false);
            }
            catch { /* swallow; reply pump dies when socket closes */ }
        }
    }

    public void Dispose()
    {
        try { _cts.Cancel(); } catch { }
        try { _listener.Close(); } catch { }
        foreach (var kv in _upstreams) kv.Value.Dispose();
        _upstreams.Clear();
        try { _recvLoop?.Wait(TimeSpan.FromSeconds(1)); } catch { }
        _cts.Dispose();
    }

    private sealed class UdpUpstream : IDisposable
    {
        private readonly UdpClient _socket;
        private readonly IPEndPoint _remote;

        public UdpUpstream(IPEndPoint remote)
        {
            _socket = new UdpClient();
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
