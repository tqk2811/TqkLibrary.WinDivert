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

    // Flows the host asked to reset — see ResetEscapedFlows. Shared by both NAT stages (one per
    // address family) and emptied flow by flow as the tracker reports closes.
    private readonly EscapedFlowBlocklist _escapedFlows = new EscapedFlowBlocklist();

    private ISocketTracker? _tracker;
    private ITcpRelayServer? _tcpRelay;
    private IUdpRelayServer? _udpRelay;
    private IPacketPump? _ipv4Pump;
    private IPacketPump? _ipv6Pump;
    // The reply legs of the redirect pumps, on handles of their own — see RedirectFilter.
    private IPacketPump? _ipv4ReplyPump;
    private IPacketPump? _ipv6ReplyPump;
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

    /// <summary>
    /// Raised when one of the capture handles stops. Traffic that handle covered is no longer
    /// being redirected — for an unexpected stop that means the target's packets are now going
    /// out as they are, which the user needs telling about.
    /// </summary>
    public event Action<PumpStop>? PumpStopped;

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

    public int ResetEscapedFlows()
    {
        if (_tracker is null) throw new InvalidOperationException("Redirector not started");

        // A tracked TCP flow with no NAT entry is one the relay never saw: its handshake happened
        // before the process was attached. Everything the relay carries has an entry under its
        // source port, so this is exactly the set that has been passing through.
        int marked = 0;
        foreach (FlowKey flow in _tracker.TcpSnapshot)
        {
            if (flow.Protocol != 6) continue;
            if (_nat.Find(6, flow.LocalPort, IsIpv6Flow(flow)) != null) continue;
            if (_escapedFlows.Add(flow)) marked++;
        }
        _logger.LogInformation("{Count} pre-existing flow(s) marked for reset; each is answered with an RST on its next packet", marked);
        return marked;
    }

    public void Start()
    {
        if (_tracker != null) throw new InvalidOperationException("Already started");

        _logger.LogInformation(
            "starting redirect for pid={Pid}, protocols={Protocols}, ipv6={Ipv6Mode}, netPriority={NetPriority}",
            _options.ProcessId, _options.Protocols, _options.Ipv6Mode, _options.NetworkPriority);

        try
        {
            StartCore();
        }
        catch
        {
            // Half of this is already running by the time the network handle is opened — the
            // tracker, two relay listeners, their accept loops. Opening that handle is also the
            // step that fails when the tool is not elevated, and a caller told "Start threw" does
            // not go on to call Dispose. Everything stood up so far comes down here instead.
            try { Dispose(); } catch (Exception cleanup) { _logger.LogDebug(cleanup, "cleaning up after a failed start"); }
            throw;
        }
    }

    private void StartCore()
    {
        ISocketTracker tracker = _trackerFactory.Create(
            _options.ProcessId, _options.SocketPriority, _options.ShouldTrackProcess);
        _tracker = tracker;
        tracker.TcpConnectEstablished += k => TcpConnectEstablished?.Invoke(k);
        tracker.TcpConnectClosed += k => TcpConnectClosed?.Invoke(k);
        // A flow marked for reset is done with once the process has closed it.
        tracker.TcpConnectClosed += k => _escapedFlows.Remove(k);
        // And its NAT entry stops being the truth about that port. The tracker is the only thing
        // that knows a flow ended, so without this the table only ever grows and stale entries
        // answer for ports the OS has since handed to somebody else.
        tracker.TcpConnectClosed += k => _nat.MarkClosed(k.Protocol, k.LocalPort, IsIpv6Flow(k));
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

        if (_options.SecureDnsDecider != null)
        {
            // The caller picks a resolver per query and owns them all; none is created here.
            _logger.LogInformation("secure DNS enabled machine-wide, resolver chosen per query");
        }
        else if (_options.EnableSecureDns)
        {
            // One resolver shared by both pumps, so IPv4 and IPv6 queries ride the same HTTPS
            // connection pool.
            _dnsResolver = _dnsResolverFactory.Create(_options.DohEndpoint);
            _logger.LogInformation("secure DNS enabled for {Scope}, resolving over {Endpoint}",
                _options.SecureDnsScope, _dnsResolver.Endpoint);
        }

        StartIpv4Pump(tracker, ports);

        if (ipv6Mode == Ipv6Mode.Redirect) StartIpv6RedirectPump(tracker, ports);
        else if (ipv6Mode == Ipv6Mode.Block) StartIpv6BlockPump(tracker);
        else if (WantsMachineWideSecureDns && Socket.OSSupportsIPv6) StartIpv6SecureDnsPump(tracker);
    }

    /// <summary>
    /// Which of the two port spaces a flow belongs to. A v4-mapped address is an IPv4 flow riding
    /// a dual-stack socket, and its port lives in the IPv4 space — the NAT key has to agree.
    /// </summary>
    private static bool IsIpv6Flow(FlowKey flow)
        => flow.LocalAddress.AddressFamily == AddressFamily.InterNetworkV6
            && !flow.LocalAddress.IsIPv4MappedToIPv6;

    private void OnPumpStopped(PumpStop stop)
    {
        if (!stop.IsOrderly)
            _logger.LogError(
                "[{Pump}] capture stopped with win32={Win32}; traffic on this handle is no longer redirected",
                stop.PumpName, stop.Win32Error);

        PumpStopped?.Invoke(stop);
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
        || WantsSecureDns || _options.BlockUnhandledTargetUdp || _options.EnableDnsSniff;

    private void StartIpv4Pump(ISocketTracker tracker, RelayPorts ports)
    {
        RelayPorts natPorts = RelayPorts.Ipv4Only(ports.Tcp, ports.Udp);

        // The reply leg first: once the egress handle bends a SYN onto the relay, the relay's
        // SYN-ACK must already have a handle to bend it back, or the process gets it from loopback
        // and resets the connection.
        if (SplitsReplyLeg)
            _ipv4ReplyPump = StartRelayReplyPump("ipv4-reply", ipv6: false, tracker, natPorts, ports.Tcp, ports.Udp);

        // Only what a stage on this handle can act on — see RedirectFilter.
        string filter = SplitsReplyLeg
            ? RedirectFilter.BuildEgress(ipv6: false, WantsTcp, CapturesUdp, _options.EnableDnsSniff)
            : BuildRedirectFilter(ipv6: false, ports.Tcp, ports.Udp);
        _logger.LogDebug("opening IPv4 NETWORK handle, filter={Filter}", filter);
        IWinDivertHandle handle = OpenNetworkHandle(filter);

        var builder = new PacketPipelineBuilder();

        // Learn IP -> domain from DNS answers before anything can claim or rewrite them. Answers
        // never belong to the egress or reply legs NAT handles, so ordering is free here; putting
        // it first just guarantees it also sees answers a later stage might drop.
        if (_options.EnableDnsSniff)
        {
            builder.Use(CreateDnsSniffMiddleware());
            _logger.LogDebug("DNS answer sniffing enabled");
        }

        // DNS-over-HTTPS runs before NAT so it claims DNS/53 first.
        if (WantsSecureDns) builder.Use(CreateSecureDnsMiddleware(tracker));

        builder.Use(CreateNatMiddleware(tracker, natPorts));
        AddTrailingMiddlewares(builder, tracker);

        _ipv4Pump = _pumpFactory.Create("ipv4", handle, builder.Build(), CreateBypass(tracker, natPorts));
        _ipv4Pump.Stopped += OnPumpStopped;
        _ipv4Pump.Start();
    }

    // The same NAT stage as IPv4, pointed at the relay's [::1] listeners, so an IPv6 connection
    // reaches the connection handler exactly like an IPv4 one.
    private void StartIpv6RedirectPump(ISocketTracker tracker, RelayPorts ports)
    {
        RelayPorts natPorts = RelayPorts.Ipv6Only(ports.TcpV6, ports.UdpV6);
        if (SplitsReplyLeg)
            _ipv6ReplyPump = StartRelayReplyPump("ipv6-reply", ipv6: true, tracker, natPorts, ports.TcpV6, ports.UdpV6);

        string filter = SplitsReplyLeg
            ? RedirectFilter.BuildEgress(ipv6: true, WantsTcp, CapturesUdp, _options.EnableDnsSniff)
            : BuildRedirectFilter(ipv6: true, ports.TcpV6, ports.UdpV6);
        _logger.LogDebug("opening IPv6 NETWORK handle for redirect, filter={Filter}", filter);
        IWinDivertHandle handle = OpenNetworkHandle(filter);

        var builder = new PacketPipelineBuilder();

        // DNS answers travelling over IPv6 name the same servers as the IPv4 ones; feeding them to
        // the same table is what lets a v6-only connection be routed by domain.
        if (_options.EnableDnsSniff) builder.Use(CreateDnsSniffMiddleware());

        // DNS-over-HTTPS before NAT, only machine-wide: then DNS/53 over IPv6 is answered over HTTPS
        // like IPv4. Tracked-only keeps the old behaviour — v6 DNS is NAT-routed like other UDP.
        if (WantsMachineWideSecureDns) builder.Use(CreateSecureDnsMiddleware(tracker));
        builder.Use(CreateNatMiddleware(tracker, natPorts));
        AddTrailingMiddlewares(builder, tracker);

        _ipv6Pump = _pumpFactory.Create("ipv6", handle, builder.Build(), CreateBypass(tracker, natPorts));
        _ipv6Pump.Stopped += OnPumpStopped;
        _ipv6Pump.Start();
    }

    // A caller's own stages may want any packet on one handle, so with them the legs stay together.
    private bool SplitsReplyLeg => _options.ConfigureNetworkPipeline == null;

    // Only the NAT stage: nothing else acts on loopback packets from a relay port (DNS sniffing
    // wants source port 53, DoH and the UDP block want egress on a real interface). A NAT instance
    // of its own, sharing the table, so no per-handle state (held SYNs) is touched from two threads.
    private IPacketPump? StartRelayReplyPump(
        string name, bool ipv6, ISocketTracker tracker, RelayPorts natPorts, int tcpRelayPort, int udpRelayPort)
    {
        string? filter = RedirectFilter.BuildRelayReply(ipv6, WantsTcp, CapturesUdp, tcpRelayPort, udpRelayPort);
        if (filter == null) return null;
        _logger.LogDebug("opening {Pump} NETWORK handle, filter={Filter}", name, filter);
        IWinDivertHandle handle = OpenNetworkHandle(filter);

        var builder = new PacketPipelineBuilder();
        builder.Use(CreateNatMiddleware(tracker, natPorts));

        IPacketPump pump = _pumpFactory.Create(name, handle, builder.Build());
        pump.Stopped += OnPumpStopped;
        pump.Start();
        return pump;
    }

    private void StartIpv6BlockPump(ISocketTracker tracker)
    {
        const string filter = "ipv6 and (tcp or udp) and not impostor";
        _logger.LogDebug("opening IPv6 NETWORK handle to block, filter={Filter}", filter);
        IWinDivertHandle handle = OpenNetworkHandle(filter);

        var builder = new PacketPipelineBuilder();
        // Answered before the block, only machine-wide: that DoH stage must see the DNS/53 first.
        // Tracked-only keeps the old behaviour — the target's IPv6 DNS is blocked with the rest.
        if (WantsMachineWideSecureDns) builder.Use(CreateSecureDnsMiddleware(tracker));
        builder.Use(new Ipv6BlockMiddleware(tracker, _loggerFactory.CreateLogger<Ipv6BlockMiddleware>()));

        _ipv6Pump = _pumpFactory.Create("ipv6-block", handle, builder.Build());
        _ipv6Pump.Stopped += OnPumpStopped;
        _ipv6Pump.Start();
    }

    // Ipv6Mode.Ignore opens no IPv6 handle for the target, but machine-wide DNS still has to move
    // the whole machine's IPv6 DNS/53 onto DoH — otherwise the OS resolver just asks over IPv6.
    // Only outbound DNS/53 is captured; everything else on IPv6 stays untouched.
    private void StartIpv6SecureDnsPump(ISocketTracker tracker)
    {
        const string filter = "ipv6 and outbound and udp.DstPort == 53 and not impostor";
        _logger.LogDebug("opening IPv6 NETWORK handle for secure DNS, filter={Filter}", filter);
        IWinDivertHandle handle = OpenNetworkHandle(filter);

        var builder = new PacketPipelineBuilder();
        builder.Use(CreateSecureDnsMiddleware(tracker));

        _ipv6Pump = _pumpFactory.Create("ipv6-dns", handle, builder.Build());
        _ipv6Pump.Stopped += OnPumpStopped;
        _ipv6Pump.Start();
    }

    // A decider takes precedence over the fixed-resolver switches and is always machine-wide.
    private bool WantsSecureDns => _options.SecureDnsDecider != null || _options.EnableSecureDns;

    private bool WantsMachineWideSecureDns
        => _options.SecureDnsDecider != null
            || (_options.EnableSecureDns && _options.SecureDnsScope == DnsInterceptScope.WholeMachine);

    private DnsOverHttpsMiddleware CreateSecureDnsMiddleware(ISocketTracker tracker)
        => _options.SecureDnsDecider is { } decider
            ? new DnsOverHttpsMiddleware(
                decider, tracker, _dnsMessageParser,
                _loggerFactory.CreateLogger<DnsOverHttpsMiddleware>(), ReverseDns)
            : new DnsOverHttpsMiddleware(
                _dnsResolver!, tracker, _dnsMessageParser,
                _loggerFactory.CreateLogger<DnsOverHttpsMiddleware>(), ReverseDns,
                scope: _options.SecureDnsScope);

    private DnsAnswerSniffMiddleware CreateDnsSniffMiddleware()
        => new DnsAnswerSniffMiddleware(
            ReverseDns, _dnsMessageParser, _loggerFactory.CreateLogger<DnsAnswerSniffMiddleware>());

    private NatRedirectMiddleware CreateNatMiddleware(ISocketTracker tracker, RelayPorts ports)
        => new NatRedirectMiddleware(
            _nat, tracker, ports, _options.Protocols, _options.ProcessId,
            _loggerFactory.CreateLogger<NatRedirectMiddleware>(),
            _dnsLookupStarted ? _dnsCacheLookup : null,
            _options.RedirectDestinationPorts,
            _options.BlockEscapedFlows,
            _options.ShouldRedirectUdp,
            _escapedFlows);

    // The pump's fast path for packets no stage of a redirect pipeline would touch. Only for the
    // built-in stages: what a caller's own stage wants is unknowable, so with one configured every
    // packet takes the full pipeline. See UntrackedEgressBypass.
    private IPacketBypass? CreateBypass(ISocketTracker tracker, RelayPorts natPorts)
        => _options.ConfigureNetworkPipeline == null
            ? new UntrackedEgressBypass(tracker, natPorts, _options.Protocols)
            : null;

    // The caller's own middlewares, then the UDP block last — so everything already handled (DNS,
    // NAT, the caller's stages) has been claimed before anything is swallowed.
    private void AddTrailingMiddlewares(PacketPipelineBuilder builder, ISocketTracker tracker)
    {
        _options.ConfigureNetworkPipeline?.Invoke(builder);
        if (_options.BlockUnhandledTargetUdp)
            builder.Use(new BlockTargetUdpMiddleware(tracker, _loggerFactory.CreateLogger<BlockTargetUdpMiddleware>()));
    }

    // Packets the driver has captured wait in a queue until the pump takes them. The defaults —
    // 4096 packets, 2 seconds — are sized for a pump that never pauses; ours does, when a burst of
    // SYNs each costs a sweep of the kernel tables, and every packet still queued when the time
    // runs out is DROPPED. A dropped SYN, or the relay's SYN-ACK to it, is a handshake the process
    // only completes after its retransmission timer fires: one second, then three, then seven.
    // With the queue this deep a pause of the same length is a pause, not a loss — the browser
    // waits a moment instead of a second.
    private const ulong QueueLength = 16384;        // packets; the driver's maximum
    private const ulong QueueTimeMs = 8000;         // the driver allows up to 16000
    private const ulong QueueBytes = 16 * 1024 * 1024;

    private IWinDivertHandle OpenNetworkHandle(string filter)
    {
        IWinDivertHandle handle = _handleFactory.Open(
            filter, WinDivertLayer.Network, _options.NetworkPriority, WinDivertOpenFlags.None);
        try
        {
            handle.SetParam(WinDivertParam.QueueLength, QueueLength);
            handle.SetParam(WinDivertParam.QueueTime, QueueTimeMs);
            handle.SetParam(WinDivertParam.QueueSize, QueueBytes);
        }
        catch (Exception ex)
        {
            // The defaults still work; they just lose packets sooner under a stall.
            _logger.LogWarning(ex, "could not deepen the driver queue for filter={Filter}; keeping the defaults", filter);
        }
        return handle;
    }

    private string BuildRedirectFilter(bool ipv6, int tcpRelayPort, int udpRelayPort)
        => RedirectFilter.Build(
            ipv6, WantsTcp, CapturesUdp, tcpRelayPort, udpRelayPort,
            sniffDnsAnswers: _options.EnableDnsSniff,
            captureEverything: _options.ConfigureNetworkPipeline != null);

    /// <remarks>
    /// The relays go down BEFORE the pumps, and the order is the whole point. Closing a relay
    /// resets the loopback sockets the redirected connections are riding on, and that reset only
    /// reaches the process if the NAT stage is still there to bend it back onto the address the
    /// process believes it is talking to. Unloading the driver first — which is what this used to
    /// do — throws that reset away: every redirected socket is left ESTABLISHED with nothing on
    /// the other end, so the process (a browser holding a keep-alive pool, say) goes on believing
    /// its connections are usable long after redirection was switched off.
    /// <para>
    /// What it costs is one instant in which a SYN is still bent onto a relay port that has just
    /// closed, and the process sees a refused connection instead of a pass-through. That is the
    /// right way round: refusing a connection while the engine is coming down is honest, and the
    /// process retries; leaving a live-looking dead socket behind is not.
    /// </para>
    /// </remarks>
    public void Dispose()
    {
        _logger.LogInformation("stopping redirect for pid={Pid}", _options.ProcessId);
        _tcpRelay?.Dispose();
        _udpRelay?.Dispose();
        _ipv6Pump?.Dispose();
        _ipv4Pump?.Dispose();
        _ipv6ReplyPump?.Dispose();
        _ipv4ReplyPump?.Dispose();
        _tracker?.Dispose();
        _dnsResolver?.Dispose();
        _dnsCacheLookup.Dispose();
    }
}
