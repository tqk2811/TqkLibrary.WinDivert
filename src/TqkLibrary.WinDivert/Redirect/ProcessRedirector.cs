using System;
using TqkLibrary.WinDivert.Flow;
using TqkLibrary.WinDivert.SecureDns;
using TqkLibrary.WinDivert.Native;
using TqkLibrary.WinDivert.Pipeline;

namespace TqkLibrary.WinDivert.Redirect;

// Orchestrator. Wires up:
//   1) SocketTracker — SOCKET-layer handle scoped to the target PID
//   2) TcpRelayServer / UdpRelayServer — local loopback listeners
//   3) NatTable — shared translation state
//   4) PacketPump (NETWORK-layer handles) running middleware pipelines that rewrite/drop packets:
//        - IPv4 pump: NatRedirectMiddleware (+ user/DNS/UDP-block middlewares)
//        - IPv6 pump: Ipv6BlockMiddleware (when BlockIpv6)
//
// Lifetime: construct, call Start(), use, then Dispose().
public sealed class ProcessRedirector : IDisposable
{
    private readonly RedirectOptions _options;
    private SocketTracker? _tracker;
    private TcpRelayServer? _tcpRelay;
    private UdpRelayServer? _udpRelay;
    private PacketPump? _ipv4Pump;
    private PacketPump? _ipv6Pump;
    private DnsCacheLookup? _dnsLookup;
    private DohResolver? _dohResolver;
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

        // ---- IPv4 NETWORK pipeline ----
        // `not impostor` avoids re-capturing packets we reinjected ourselves (prevents loops).
        // The handle must also capture UDP whenever a UDP middleware is active (DNS-over-HTTPS or
        // UDP block), even if NAT itself only redirects TCP — otherwise those middlewares would
        // never see the UDP packets.
        bool captureTcp = (_options.Protocols & RedirectProtocol.Tcp) != 0;
        bool captureUdp = (_options.Protocols & RedirectProtocol.Udp) != 0
            || _options.EnableSecureDns || _options.BlockUnhandledTargetUdp;
        string proto = BuildProtoFilter(captureTcp, captureUdp);
        string v4Filter = $"ip and ({proto}) and not impostor";
        string filterDesc = (_options.RedirectDestinationPorts == null || _options.RedirectDestinationPorts.Count == 0)
            ? "all"
            : string.Join(",", _options.RedirectDestinationPorts);
        DiagnosticLogger.Log("INT", $"Open filter=\"{v4Filter}\" priority={_options.NetworkPriority} tcpRelay={tcpPort} udpRelay={udpPort} pid={_options.ProcessId} dstPortFilter={filterDesc}");
        WinDivertHandle v4Handle = WinDivertHandle.Open(v4Filter, WinDivertLayer.Network, _options.NetworkPriority, WinDivertOpenFlags.None);

        var v4Builder = new PacketPipelineBuilder();
        // DNS-over-HTTPS runs FIRST so it claims the target's DNS/53 before NAT could redirect it.
        if (_options.EnableSecureDns)
        {
            _dohResolver = new DohResolver(_options.DohEndpoint);
            v4Builder.Use(new DnsOverHttpsMiddleware(_dohResolver));
            DiagnosticLogger.Log("RDR", $"Secure DNS ENABLED via DoH {_options.DohEndpoint}");
        }
        // NAT redirect (egress + loopback-reply legs) for the enabled protocols.
        v4Builder.Use(new NatRedirectMiddleware(tcpPort, udpPort, _options.Protocols, _options.RedirectDestinationPorts));
        // Let callers insert their own middlewares (composable pipeline).
        _options.ConfigureNetworkPipeline?.Invoke(v4Builder);
        // Drop any remaining target UDP last, so handled UDP (DNS above, NAT, user) is already claimed.
        if (_options.BlockUnhandledTargetUdp)
        {
            v4Builder.Use(new BlockTargetUdpMiddleware());
            DiagnosticLogger.Log("RDR", "Block-unhandled-target-UDP ENABLED");
        }

        _ipv4Pump = new PacketPump("INT", v4Handle, v4Builder.Build(), _tracker, _nat, _options.ProcessId, _dnsLookup);
        _ipv4Pump.Start();

        // ---- IPv6 NETWORK pipeline: drop the target's IPv6 (the IPv4 pump is v4-only, so v6
        // would otherwise leak the real address). Non-target v6 traffic is passed through. ----
        if (_options.BlockIpv6)
        {
            string v6Filter = "ipv6 and (tcp or udp) and not impostor";
            DiagnosticLogger.Log("V6X", $"Open filter=\"{v6Filter}\" priority={_options.NetworkPriority}");
            WinDivertHandle v6Handle = WinDivertHandle.Open(v6Filter, WinDivertLayer.Network, _options.NetworkPriority, WinDivertOpenFlags.None);
            var v6Builder = new PacketPipelineBuilder();
            v6Builder.Use(new Ipv6BlockMiddleware());
            _ipv6Pump = new PacketPump("V6X", v6Handle, v6Builder.Build(), _tracker, _nat, _options.ProcessId, _dnsLookup);
            _ipv6Pump.Start();
        }
    }

    private static string BuildProtoFilter(bool tcp, bool udp)
    {
        if (tcp && udp) return "tcp or udp";
        if (tcp) return "tcp";
        if (udp) return "udp";
        return "false";
    }

    public void Dispose()
    {
        DiagnosticLogger.Log("RDR", "Dispose");
        _ipv6Pump?.Dispose();
        _ipv4Pump?.Dispose();
        _tcpRelay?.Dispose();
        _udpRelay?.Dispose();
        _tracker?.Dispose();
        _dohResolver?.Dispose();
        _dnsLookup?.Dispose();
        DiagnosticLogger.Close();
    }
}
