using System;
using TqkLibrary.WinDivert.Flow;

namespace TqkLibrary.WinDivert.Redirect;

// Orchestrator. Wires up:
//   1) SocketTracker — SOCKET-layer handle scoped to the target PID
//   2) TcpRelayServer / UdpRelayServer — local loopback listeners
//   3) NatTable — shared translation state
//   4) PacketInterceptor — NETWORK-layer handle that rewrites headers
//
// Lifetime: construct, call Start(), use, then Dispose().
public sealed class ProcessRedirector : IDisposable
{
    private readonly RedirectOptions _options;
    private SocketTracker? _tracker;
    private TcpRelayServer? _tcpRelay;
    private UdpRelayServer? _udpRelay;
    private PacketInterceptor? _interceptor;
    private readonly NatTable _nat = new();

    public NatTable Nat => _nat;
    public int TcpRelayPort => _tcpRelay?.Port ?? 0;
    public int UdpRelayPort => _udpRelay?.Port ?? 0;

    public event Action<FlowKey>? TcpConnectEstablished;
    public event Action<FlowKey>? TcpConnectClosed;

    public ProcessRedirector(RedirectOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        if (options.ProcessId == 0) throw new ArgumentException("ProcessId is required", nameof(options));
        if (options.Protocols == RedirectProtocol.None) throw new ArgumentException("At least one protocol required", nameof(options));
    }

    public void Start()
    {
        _tracker = new SocketTracker(_options.ProcessId);
        _tracker.TcpConnectEstablished += k => TcpConnectEstablished?.Invoke(k);
        _tracker.TcpConnectClosed += k => TcpConnectClosed?.Invoke(k);
        _tracker.Start();

        int tcpPort = 0, udpPort = 0;
        if ((_options.Protocols & RedirectProtocol.Tcp) != 0)
        {
            _tcpRelay = new TcpRelayServer(_nat, _options.TcpConnectionHandler);
            _tcpRelay.Start();
            tcpPort = _tcpRelay.Port;
        }
        if ((_options.Protocols & RedirectProtocol.Udp) != 0)
        {
            _udpRelay = new UdpRelayServer(_nat, _options.UdpDatagramHandler);
            _udpRelay.Start();
            udpPort = _udpRelay.Port;
        }

        _interceptor = new PacketInterceptor(_tracker, _nat, _options.ProcessId, tcpPort, udpPort, _options.Protocols);
        _interceptor.Start(_options.NetworkPriority);
    }

    public void Dispose()
    {
        _interceptor?.Dispose();
        _tcpRelay?.Dispose();
        _udpRelay?.Dispose();
        _tracker?.Dispose();
    }
}
