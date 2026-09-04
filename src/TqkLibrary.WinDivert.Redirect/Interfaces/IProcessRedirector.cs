using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace TqkLibrary.WinDivert.Redirect.Interfaces;

/// <summary>
/// One redirect session: the target processes, the loopback relay their traffic is bent onto, and
/// the packet pipelines that do the bending. Construct through
/// <see cref="IProcessRedirectorFactory"/>, call <see cref="Start"/>, use, then dispose.
/// </summary>
public interface IProcessRedirector : IDisposable
{
    /// <summary>The flows this session has redirected. Exposed for diagnostics and for a handler
    /// that needs to look up where a connection was really going.</summary>
    INatTable Nat { get; }

    /// <summary>Loopback port of the IPv4 TCP relay; 0 when TCP is not being redirected.</summary>
    int TcpRelayPort { get; }
    int UdpRelayPort { get; }

    /// <summary>Loopback ports of the IPv6 relay listeners; 0 when IPv6 is not being redirected.</summary>
    int TcpRelayPortV6 { get; }
    int UdpRelayPortV6 { get; }

    /// <summary>
    /// IP to domain learned from DNS answers (sniffed and/or resolved over HTTPS). Populated only
    /// while the matching option is on, but never null — so a connection handler can query it
    /// without a null check.
    /// </summary>
    IReverseDnsTable ReverseDns { get; }

    /// <summary>
    /// Best-effort IP to name from the machine DNS cache, for annotating what the user sees. Null
    /// while <see cref="RedirectOptions.EnableDnsLookup"/> is off. Routing should prefer
    /// <see cref="ReverseDns"/>, which does not depend on the OS resolver having asked.
    /// </summary>
    IDnsCacheLookup? DnsLookup { get; }

    /// <summary>Process ids currently in the redirect scope.</summary>
    IReadOnlyCollection<uint> TrackedProcessIds { get; }

    /// <summary>Raised when the SOCKET layer sees a tracked process open / close a TCP flow.</summary>
    event Action<FlowKey>? TcpConnectEstablished;
    event Action<FlowKey>? TcpConnectClosed;

    /// <summary>Raised when the relay accepts / finishes a redirected TCP connection.</summary>
    event Action<RedirectedTcpConnection>? TcpConnectionOpened;
    event Action<RedirectedTcpConnection>? TcpConnectionClosed;

    /// <summary>
    /// Opens the driver handles and starts pumping. Throws
    /// <see cref="System.ComponentModel.Win32Exception"/> when the driver refuses — most often
    /// because the process is not elevated.
    /// </summary>
    void Start();

    /// <summary>
    /// Brings another process into the redirect scope, so its new connections are captured like
    /// the root target's. For an external tree monitor following child processes. Idempotent.
    /// </summary>
    void AddTrackedProcessId(uint pid);

    /// <summary>
    /// Drops a process from the scope: its SOCKET handle is closed and its flows forgotten, so new
    /// connections go out untouched. Connections it already has through the relay keep running
    /// until they close on their own. False when the pid was not tracked.
    /// </summary>
    bool RemoveTrackedProcessId(uint pid);

    bool IsTrackedProcessId(uint pid);

    /// <summary>
    /// Delivers a UDP datagram to the target process as if it came from the original destination.
    /// For a handler that took over UDP forwarding itself (SOCKS5 UDP ASSOCIATE, say) and receives
    /// replies the relay's own upstream socket never sees.
    /// </summary>
    /// <param name="isIpv6">
    /// Must match the family of the flow, or the NAT stage will not recognise the reply.
    /// </param>
    Task InjectUdpReplyToProcessAsync(ushort processClientPort, byte[] payload, bool isIpv6 = false);
}
