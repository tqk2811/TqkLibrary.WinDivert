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
    private Ipv6Blocker? _ipv6Blocker;
    private DnsCacheLookup? _dnsLookup;
    private readonly NatTable _nat = new();

    public NatTable Nat => _nat;
    public int TcpRelayPort => _tcpRelay?.Port ?? 0;
    public int UdpRelayPort => _udpRelay?.Port ?? 0;
    public DnsCacheLookup? DnsLookup => _dnsLookup;

    /// <summary>
    /// Inject a UDP datagram back to the target process as if it came from the original
    /// destination. Used by handlers that take over UDP forwarding (e.g. SOCKS5 UDP ASSOCIATE)
    /// and need to deliver replies the relay's default upstream socket never sees.
    /// </summary>
    public Task InjectUdpReplyToProcessAsync(ushort processClientPort, byte[] payload)
    {
        if (_udpRelay is null) throw new InvalidOperationException("UDP redirect is not enabled");
        return _udpRelay.InjectReplyToProcessAsync(processClientPort, payload);
    }

    /// <summary>
    /// Add an additional process id to the redirect scope. Used by external tree monitors to
    /// pull child processes into the same SocketTracker so their TCP/UDP traffic is captured
    /// just like the root target's. Idempotent — adding the same pid twice is a no-op.
    /// </summary>
    public void AddTrackedProcessId(uint pid)
    {
        if (_tracker is null) throw new InvalidOperationException("Redirector not started");
        _tracker.AddProcess(pid);
    }

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
        DiagnosticLogger.Configure(_options.LogFilePath);
        DiagnosticLogger.Log("RDR", $"Start pid={_options.ProcessId} protocols={_options.Protocols} netPri={_options.NetworkPriority} sockPri={_options.SocketPriority}");

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

        DiagnosticLogger.Log("RDR", $"Relay ports tcp={tcpPort} udp={udpPort}");

        if (_options.EnableDnsLookup)
        {
            _dnsLookup = new DnsCacheLookup();
            _dnsLookup.Start();
            DiagnosticLogger.Log("RDR", "DNS cache lookup ENABLED");
        }

        _interceptor = new PacketInterceptor(_tracker, _nat, _options.ProcessId, tcpPort, udpPort, _options.Protocols, _options.RedirectDestinationPorts, _dnsLookup);
        _interceptor.Start(_options.NetworkPriority);

        if (_options.BlockIpv6)
        {
            _ipv6Blocker = new Ipv6Blocker(_tracker);
            _ipv6Blocker.Start(_options.NetworkPriority);
        }
    }

    public void Dispose()
    {
        DiagnosticLogger.Log("RDR", "Dispose");
        _ipv6Blocker?.Dispose();
        _interceptor?.Dispose();
        _tcpRelay?.Dispose();
        _udpRelay?.Dispose();
        _tracker?.Dispose();
        _dnsLookup?.Dispose();
        DiagnosticLogger.Close();
    }
}
