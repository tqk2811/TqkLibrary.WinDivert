using System;
using System.Collections.Generic;
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
    private readonly RedirectLogger _log;
    // True when this redirector created the logger and must dispose it. A logger handed in through
    // RedirectOptions.Logger belongs to the caller.
    private readonly bool _ownsLog;
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
    /// IP -&gt; domain learned from DNS answers (classic sniff and/or DoH). Populated only while
    /// RedirectOptions.EnableDnsSniff or EnableSecureDns is on; always non-null so a connection
    /// handler can query it without a null check.
    /// </summary>
    public ReverseDnsTable ReverseDns { get; } = new ReverseDnsTable();

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

    /// <summary>
    /// Drop a process from the redirect scope: its SOCKET handle is closed and its flows forgotten,
    /// so new connections go out untouched. Returns false when the pid wasn't tracked. Existing
    /// relayed connections of that process keep running until they close on their own.
    /// </summary>
    public bool RemoveTrackedProcessId(uint pid)
    {
        if (_tracker is null) throw new InvalidOperationException("Redirector not started");
        return _tracker.RemoveProcess(pid);
    }

    /// <summary>Process ids currently in the redirect scope.</summary>
    public IReadOnlyCollection<uint> TrackedProcessIds
        => _tracker?.TrackedProcessIds ?? Array.Empty<uint>();

    public bool IsTrackedProcessId(uint pid) => _tracker?.IsTrackedProcess(pid) == true;

    public event Action<FlowKey>? TcpConnectEstablished;
    public event Action<FlowKey>? TcpConnectClosed;

    /// <summary>Raised when the relay accepts / finishes a redirected TCP connection.</summary>
    public event Action<RedirectedTcpConnection>? TcpConnectionOpened;
    public event Action<RedirectedTcpConnection>? TcpConnectionClosed;

    /// <summary>Diagnostic sink used by every component of this redirector.</summary>
    public RedirectLogger Logger => _log;

    public ProcessRedirector(RedirectOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        // ProcessId 0 is allowed: the redirector then starts with an empty scope and the caller
        // feeds pids in with AddTrackedProcessId as a process watcher discovers them.
        if (options.Protocols == RedirectProtocol.None) throw new ArgumentException("At least one protocol required", nameof(options));

        if (options.Logger != null)
        {
            _log = options.Logger;
            _ownsLog = false;
        }
        else
        {
            _log = new RedirectLogger(options.LoggerFactory, options.LogFilePath);
            _ownsLog = true;
        }
    }

    public void Start()
    {
        _log.Log("RDR", $"Start pid={_options.ProcessId} protocols={_options.Protocols} netPri={_options.NetworkPriority} sockPri={_options.SocketPriority}");

        _tracker = new SocketTracker(_options.ProcessId, _log, _options.SocketPriority);
        _tracker.TcpConnectEstablished += k => TcpConnectEstablished?.Invoke(k);
        _tracker.TcpConnectClosed += k => TcpConnectClosed?.Invoke(k);
        _tracker.Start();

        int tcpPort = 0, udpPort = 0;
        if ((_options.Protocols & RedirectProtocol.Tcp) != 0)
        {
            _tcpRelay = new TcpRelayServer(_nat, _options.TcpConnectionHandler, _log);
            _tcpRelay.ConnectionOpened += c => TcpConnectionOpened?.Invoke(c);
            _tcpRelay.ConnectionClosed += c => TcpConnectionClosed?.Invoke(c);
            _tcpRelay.Start();
            tcpPort = _tcpRelay.Port;
        }
        if ((_options.Protocols & RedirectProtocol.Udp) != 0)
        {
            _udpRelay = new UdpRelayServer(_nat, _options.UdpDatagramHandler);
            _udpRelay.Start();
            udpPort = _udpRelay.Port;
        }

        _log.Log("RDR", $"Relay ports tcp={tcpPort} udp={udpPort}");

        if (_options.EnableDnsLookup)
        {
            _dnsLookup = new DnsCacheLookup();
            _dnsLookup.Start();
            _log.Log("RDR", "DNS cache lookup ENABLED");
        }

        // ---- IPv4 NETWORK pipeline ----
        // `not impostor` avoids re-capturing packets we reinjected ourselves (prevents loops).
        // The handle must also capture UDP whenever a UDP middleware is active (DNS-over-HTTPS or
        // UDP block), even if NAT itself only redirects TCP — otherwise those middlewares would
        // never see the UDP packets.
        bool captureTcp = (_options.Protocols & RedirectProtocol.Tcp) != 0;
        bool captureUdp = (_options.Protocols & RedirectProtocol.Udp) != 0
            || _options.EnableSecureDns || _options.BlockUnhandledTargetUdp || _options.EnableDnsSniff;
        string proto = BuildProtoFilter(captureTcp, captureUdp);
        string v4Filter = $"ip and ({proto}) and not impostor";
        string filterDesc = (_options.RedirectDestinationPorts == null || _options.RedirectDestinationPorts.Count == 0)
            ? "all"
            : string.Join(",", _options.RedirectDestinationPorts);
        _log.Log("INT", $"Open filter=\"{v4Filter}\" priority={_options.NetworkPriority} tcpRelay={tcpPort} udpRelay={udpPort} pid={_options.ProcessId} dstPortFilter={filterDesc}");
        WinDivertHandle v4Handle = WinDivertHandle.Open(v4Filter, WinDivertLayer.Network, _options.NetworkPriority, WinDivertOpenFlags.None);

        var v4Builder = new PacketPipelineBuilder();
        // Learn IP -> domain from DNS answers before anything can claim or rewrite them. Answers
        // never belong to the egress or reply legs NAT handles, so ordering is free here; putting
        // it first just guarantees it also sees answers a later stage might drop.
        if (_options.EnableDnsSniff)
        {
            v4Builder.Use(new DnsAnswerSniffMiddleware(ReverseDns));
            _log.Log("RDR", "DNS answer sniffing ENABLED");
        }
        // DNS-over-HTTPS runs before NAT so it claims the target's DNS/53 before NAT could redirect it.
        if (_options.EnableSecureDns)
        {
            _dohResolver = new DohResolver(_options.DohEndpoint, logger: _log);
            v4Builder.Use(new DnsOverHttpsMiddleware(_dohResolver, ReverseDns));
            _log.Log("RDR", $"Secure DNS ENABLED via DoH {_options.DohEndpoint}");
        }
        // NAT redirect (egress + loopback-reply legs) for the enabled protocols.
        v4Builder.Use(new NatRedirectMiddleware(tcpPort, udpPort, _options.Protocols, _options.RedirectDestinationPorts));
        // Let callers insert their own middlewares (composable pipeline).
        _options.ConfigureNetworkPipeline?.Invoke(v4Builder);
        // Drop any remaining target UDP last, so handled UDP (DNS above, NAT, user) is already claimed.
        if (_options.BlockUnhandledTargetUdp)
        {
            v4Builder.Use(new BlockTargetUdpMiddleware());
            _log.Log("RDR", "Block-unhandled-target-UDP ENABLED");
        }

        _ipv4Pump = new PacketPump("INT", v4Handle, v4Builder.Build(), _tracker, _nat, _options.ProcessId, _dnsLookup, _log);
        _ipv4Pump.Start();

        // ---- IPv6 NETWORK pipeline: drop the target's IPv6 (the IPv4 pump is v4-only, so v6
        // would otherwise leak the real address). Non-target v6 traffic is passed through. ----
        if (_options.BlockIpv6)
        {
            string v6Filter = "ipv6 and (tcp or udp) and not impostor";
            _log.Log("V6X", $"Open filter=\"{v6Filter}\" priority={_options.NetworkPriority}");
            WinDivertHandle v6Handle = WinDivertHandle.Open(v6Filter, WinDivertLayer.Network, _options.NetworkPriority, WinDivertOpenFlags.None);
            var v6Builder = new PacketPipelineBuilder();
            v6Builder.Use(new Ipv6BlockMiddleware());
            _ipv6Pump = new PacketPump("V6X", v6Handle, v6Builder.Build(), _tracker, _nat, _options.ProcessId, _dnsLookup, _log);
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
        _log.Log("RDR", "Dispose");
        _ipv6Pump?.Dispose();
        _ipv4Pump?.Dispose();
        _tcpRelay?.Dispose();
        _udpRelay?.Dispose();
        _tracker?.Dispose();
        _dohResolver?.Dispose();
        _dnsLookup?.Dispose();
        if (_ownsLog) _log.Dispose();
    }
}
