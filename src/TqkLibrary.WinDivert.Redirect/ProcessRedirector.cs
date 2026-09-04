using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TqkLibrary.WinDivert.SecureDns;

namespace TqkLibrary.WinDivert.Redirect;

/// <summary>
/// The orchestrator of one redirect session. It owns, and wires together:
/// the socket tracker (SOCKET-layer handles scoped to the target pids), the loopback relay
/// servers, the shared NAT table, and one packet pump per address family running a middleware
/// pipeline that rewrites or drops packets.
/// </summary>
/// <remarks>
/// The IPv4 pipeline always runs the NAT stage. What happens on IPv6 depends on
/// <see cref="RedirectOptions.Ipv6Mode"/> and on what the machine can actually deliver:
/// the same NAT pipeline pointed at the relay's [::1] listeners (Redirect), a stage that drops the
/// target's IPv6 so it falls back to IPv4 (Block), or no IPv6 handle at all (Ignore).
///
/// Every fallback here is chosen to fail SAFE. No IPv6 stack at all means Ignore — there is
/// nothing to leak. A stack but no usable [::1] relay means Block, not Ignore: a stall the user
/// can see beats traffic quietly leaving unproxied.
/// </remarks>
public sealed class ProcessRedirector : IProcessRedirector
{
    private readonly RedirectOptions _options;
    private readonly IWinDivertHandleFactory _handleFactory;
    private readonly ISocketTrackerFactory _trackerFactory;
    private readonly IPacketPumpFactory _pumpFactory;
    private readonly IDnsMessageParser _dnsMessageParser;
    private readonly IDnsResolverFactory _dnsResolverFactory;
    private readonly IDnsCacheLookup _dnsCacheLookup;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger<ProcessRedirector> _logger;

    private readonly NatTable _nat = new NatTable();

    private ISocketTracker? _tracker;
    private ITcpRelayServer? _tcpRelay;
    private IUdpRelayServer? _udpRelay;
    private IPacketPump? _ipv4Pump;
    private IPacketPump? _ipv6Pump;
    private IDnsResolver? _dnsResolver;
    private bool _dnsLookupStarted;

    public INatTable Nat => _nat;
    public IReverseDnsTable ReverseDns { get; }

    public int TcpRelayPort => _tcpRelay?.Port ?? 0;
    public int UdpRelayPort => _udpRelay?.Port ?? 0;
    public int TcpRelayPortV6 => _tcpRelay?.PortV6 ?? 0;
    public int UdpRelayPortV6 => _udpRelay?.PortV6 ?? 0;

    public IDnsCacheLookup? DnsLookup => _dnsLookupStarted ? _dnsCacheLookup : null;

    public IReadOnlyCollection<uint> TrackedProcessIds
        => _tracker?.TrackedProcessIds ?? Array.Empty<uint>();

    public event Action<FlowKey>? TcpConnectEstablished;
    public event Action<FlowKey>? TcpConnectClosed;
    public event Action<RedirectedTcpConnection>? TcpConnectionOpened;
    public event Action<RedirectedTcpConnection>? TcpConnectionClosed;

    public ProcessRedirector(
        RedirectOptions options,
        IWinDivertHandleFactory handleFactory,
        ISocketTrackerFactory trackerFactory,
        IPacketPumpFactory pumpFactory,
        IDnsMessageParser dnsMessageParser,
        IDnsResolverFactory dnsResolverFactory,
        IReverseDnsTable reverseDns,
        IDnsCacheLookup dnsCacheLookup,
        ILoggerFactory loggerFactory)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _handleFactory = handleFactory ?? throw new ArgumentNullException(nameof(handleFactory));
        _trackerFactory = trackerFactory ?? throw new ArgumentNullException(nameof(trackerFactory));
        _pumpFactory = pumpFactory ?? throw new ArgumentNullException(nameof(pumpFactory));
        _dnsMessageParser = dnsMessageParser ?? throw new ArgumentNullException(nameof(dnsMessageParser));
        _dnsResolverFactory = dnsResolverFactory ?? throw new ArgumentNullException(nameof(dnsResolverFactory));
        ReverseDns = reverseDns ?? throw new ArgumentNullException(nameof(reverseDns));
        _dnsCacheLookup = dnsCacheLookup ?? throw new ArgumentNullException(nameof(dnsCacheLookup));
        _loggerFactory = loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory));
        _logger = loggerFactory.CreateLogger<ProcessRedirector>();

        // ProcessId 0 is allowed: the session then starts with an empty scope and the caller feeds
        // pids in as a process watcher discovers them.
        if (options.Protocols == RedirectProtocol.None)
            throw new ArgumentException("At least one protocol is required", nameof(options));
    }

    public Task InjectUdpReplyToProcessAsync(ushort processClientPort, byte[] payload, bool isIpv6 = false)
    {
        if (_udpRelay is null) throw new InvalidOperationException("UDP redirect is not enabled");
        return _udpRelay.InjectReplyToProcessAsync(processClientPort, payload, isIpv6);
    }

    public void AddTrackedProcessId(uint pid)
    {
        if (_tracker is null) throw new InvalidOperationException("Redirector not started");
        _tracker.AddProcess(pid);
    }

    public bool RemoveTrackedProcessId(uint pid)
    {
        if (_tracker is null) throw new InvalidOperationException("Redirector not started");
        return _tracker.RemoveProcess(pid);
    }

    public bool IsTrackedProcessId(uint pid) => _tracker?.IsTrackedProcess(pid) == true;

    public void Start()
    {
        if (_tracker != null) throw new InvalidOperationException("Already started");

        _logger.LogInformation(
            "starting redirect for pid={Pid}, protocols={Protocols}, ipv6={Ipv6Mode}, netPriority={NetPriority}",
            _options.ProcessId, _options.Protocols, _options.Ipv6Mode, _options.NetworkPriority);

        ISocketTracker tracker = _trackerFactory.Create(_options.ProcessId, _options.SocketPriority);
        _tracker = tracker;
        tracker.TcpConnectEstablished += k => TcpConnectEstablished?.Invoke(k);
        tracker.TcpConnectClosed += k => TcpConnectClosed?.Invoke(k);
        tracker.Start();

        Ipv6Mode ipv6Mode = ResolveIpv6Mode();
        RelayPorts ports = StartRelays(ipv6Mode == Ipv6Mode.Redirect);

        // The relay could not take a loopback IPv6 socket, so nothing can be redirected there.
        if (ipv6Mode == Ipv6Mode.Redirect && !HasEveryEnabledIpv6Relay(ports))
        {
            ipv6Mode = Ipv6Mode.Block;
            _logger.LogWarning("no IPv6 loopback relay available — blocking the target's IPv6 instead, so nothing leaks out unproxied");
        }

        if (_options.EnableDnsLookup)
        {
            _dnsCacheLookup.Start();
            _dnsLookupStarted = true;
            _logger.LogDebug("DNS cache lookup enabled");
        }

        StartIpv4Pump(tracker, ports);

        if (ipv6Mode == Ipv6Mode.Redirect) StartIpv6RedirectPump(tracker, ports);
        else if (ipv6Mode == Ipv6Mode.Block) StartIpv6BlockPump(tracker);
    }

    // The mode we can actually deliver, which is not always the one that was asked for.
    private Ipv6Mode ResolveIpv6Mode()
    {
        if (_options.Ipv6Mode != Ipv6Mode.Redirect) return _options.Ipv6Mode;
        if (Socket.OSSupportsIPv6) return Ipv6Mode.Redirect;

        // No IPv6 stack at all means the target cannot produce IPv6 traffic either, so there is
        // nothing to block and nothing to leak.
        _logger.LogDebug("IPv6 redirect was requested but this machine has no IPv6 stack — nothing to do");
        return Ipv6Mode.Ignore;
    }

    private RelayPorts StartRelays(bool enableIpv6)
    {
        int tcp = 0, udp = 0, tcpV6 = 0, udpV6 = 0;

        if (WantsTcp)
        {
            var relay = new TcpRelayServer(
                _nat, _options.TcpConnectionHandler, _loggerFactory.CreateLogger<TcpRelayServer>(), enableIpv6);
            relay.ConnectionOpened += c => TcpConnectionOpened?.Invoke(c);
            relay.ConnectionClosed += c => TcpConnectionClosed?.Invoke(c);
            relay.Start();
            _tcpRelay = relay;
            tcp = relay.Port;
            tcpV6 = relay.PortV6;
        }
        if (WantsUdp)
        {
            var relay = new UdpRelayServer(_nat, _options.UdpDatagramHandler, enableIpv6);
            relay.Start();
            _udpRelay = relay;
            udp = relay.Port;
            udpV6 = relay.PortV6;
        }

        var ports = new RelayPorts(tcp, udp, tcpV6, udpV6);
        _logger.LogInformation("relay listening on {Ports}", ports);
        return ports;
    }

    private bool HasEveryEnabledIpv6Relay(RelayPorts ports)
        => (!WantsTcp || ports.TcpV6 != 0) && (!WantsUdp || ports.UdpV6 != 0);

    private bool WantsTcp => (_options.Protocols & RedirectProtocol.Tcp) != 0;
    private bool WantsUdp => (_options.Protocols & RedirectProtocol.Udp) != 0;

    // The handle must capture UDP whenever a UDP middleware is active (DNS-over-HTTPS, the UDP
    // block, answer sniffing), even if NAT itself only redirects TCP — otherwise those middlewares
    // would never see the packets they exist for.
    private bool CapturesUdp => WantsUdp
        || _options.EnableSecureDns || _options.BlockUnhandledTargetUdp || _options.EnableDnsSniff;

    private void StartIpv4Pump(ISocketTracker tracker, RelayPorts ports)
    {
        // `not impostor` avoids re-capturing packets we reinjected ourselves, which would loop.
        string filter = $"ip and ({BuildProtoFilter(WantsTcp, CapturesUdp)}) and not impostor";
        _logger.LogDebug("opening IPv4 NETWORK handle, filter={Filter}", filter);
        IWinDivertHandle handle = _handleFactory.Open(
            filter, WinDivertLayer.Network, _options.NetworkPriority, WinDivertOpenFlags.None);

        var builder = new PacketPipelineBuilder();

        // Learn IP -> domain from DNS answers before anything can claim or rewrite them. Answers
        // never belong to the egress or reply legs NAT handles, so ordering is free here; putting
        // it first just guarantees it also sees answers a later stage might drop.
        if (_options.EnableDnsSniff)
        {
            builder.Use(CreateDnsSniffMiddleware());
            _logger.LogDebug("DNS answer sniffing enabled");
        }

        // DNS-over-HTTPS runs before NAT so it claims the target's DNS/53 first.
        if (_options.EnableSecureDns)
        {
            _dnsResolver = _dnsResolverFactory.Create(_options.DohEndpoint);
            builder.Use(new DnsOverHttpsMiddleware(
                _dnsResolver, tracker, _dnsMessageParser,
                _loggerFactory.CreateLogger<DnsOverHttpsMiddleware>(), ReverseDns));
            _logger.LogInformation("secure DNS enabled, resolving over {Endpoint}", _dnsResolver.Endpoint);
        }

        builder.Use(CreateNatMiddleware(tracker, RelayPorts.Ipv4Only(ports.Tcp, ports.Udp)));
        AddTrailingMiddlewares(builder, tracker);

        _ipv4Pump = _pumpFactory.Create("ipv4", handle, builder.Build());
        _ipv4Pump.Start();
    }

    // The same NAT stage as IPv4, pointed at the relay's [::1] listeners, so an IPv6 connection
    // reaches the connection handler exactly like an IPv4 one.
    private void StartIpv6RedirectPump(ISocketTracker tracker, RelayPorts ports)
    {
        string filter = $"ipv6 and ({BuildProtoFilter(WantsTcp, CapturesUdp)}) and not impostor";
        _logger.LogDebug("opening IPv6 NETWORK handle for redirect, filter={Filter}", filter);
        IWinDivertHandle handle = _handleFactory.Open(
            filter, WinDivertLayer.Network, _options.NetworkPriority, WinDivertOpenFlags.None);

        var builder = new PacketPipelineBuilder();

        // DNS answers travelling over IPv6 name the same servers as the IPv4 ones; feeding them to
        // the same table is what lets a v6-only connection be routed by domain.
        if (_options.EnableDnsSniff) builder.Use(CreateDnsSniffMiddleware());

        // DnsOverHttpsMiddleware is deliberately absent: it builds IPv4 reply packets and ignores
        // IPv6 anyway. The target's own IPv6 DNS/53 is NAT-redirected like any other UDP and gets
        // routed by policy; the OS resolver's own DNS is untouched either way.
        builder.Use(CreateNatMiddleware(tracker, RelayPorts.Ipv6Only(ports.TcpV6, ports.UdpV6)));
        AddTrailingMiddlewares(builder, tracker);

        _ipv6Pump = _pumpFactory.Create("ipv6", handle, builder.Build());
        _ipv6Pump.Start();
    }

    private void StartIpv6BlockPump(ISocketTracker tracker)
    {
        const string filter = "ipv6 and (tcp or udp) and not impostor";
        _logger.LogDebug("opening IPv6 NETWORK handle to block, filter={Filter}", filter);
        IWinDivertHandle handle = _handleFactory.Open(
            filter, WinDivertLayer.Network, _options.NetworkPriority, WinDivertOpenFlags.None);

        var builder = new PacketPipelineBuilder();
        builder.Use(new Ipv6BlockMiddleware(tracker, _loggerFactory.CreateLogger<Ipv6BlockMiddleware>()));

        _ipv6Pump = _pumpFactory.Create("ipv6-block", handle, builder.Build());
        _ipv6Pump.Start();
    }

    private DnsAnswerSniffMiddleware CreateDnsSniffMiddleware()
        => new DnsAnswerSniffMiddleware(
            ReverseDns, _dnsMessageParser, _loggerFactory.CreateLogger<DnsAnswerSniffMiddleware>());

    private NatRedirectMiddleware CreateNatMiddleware(ISocketTracker tracker, RelayPorts ports)
        => new NatRedirectMiddleware(
            _nat, tracker, ports, _options.Protocols, _options.ProcessId,
            _loggerFactory.CreateLogger<NatRedirectMiddleware>(),
            _dnsLookupStarted ? _dnsCacheLookup : null,
            _options.RedirectDestinationPorts,
            _options.BlockEscapedFlows);

    // The caller's own middlewares, then the UDP block last — so everything already handled (DNS,
    // NAT, the caller's stages) has been claimed before anything is swallowed.
    private void AddTrailingMiddlewares(PacketPipelineBuilder builder, ISocketTracker tracker)
    {
        _options.ConfigureNetworkPipeline?.Invoke(builder);
        if (_options.BlockUnhandledTargetUdp)
            builder.Use(new BlockTargetUdpMiddleware(tracker, _loggerFactory.CreateLogger<BlockTargetUdpMiddleware>()));
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
        _logger.LogInformation("stopping redirect for pid={Pid}", _options.ProcessId);
        _ipv6Pump?.Dispose();
        _ipv4Pump?.Dispose();
        _tcpRelay?.Dispose();
        _udpRelay?.Dispose();
        _tracker?.Dispose();
        _dnsResolver?.Dispose();
        _dnsCacheLookup.Dispose();
    }
}
