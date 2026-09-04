using System;
using System.Collections.Generic;
using System.Net;

namespace TqkLibrary.WinDivert.Flow.Interfaces;

/// <summary>
/// Knows which TCP flows and UDP binds belong to the processes being followed, and which process
/// owns each one. This is what lets a packet middleware tell the target's traffic apart from
/// everything else on the machine.
/// </summary>
/// <remarks>
/// Learned from the WinDivert SOCKET layer, whose CONNECT event fires BEFORE the SYN goes out, and
/// reconciled against the kernel's own TCP/UDP tables to cover the races that event stream cannot
/// win on its own.
/// </remarks>
public interface ISocketTracker : IDisposable
{
    /// <summary>Fired when a TCP flow of a tracked process appears / goes away.</summary>
    event Action<FlowKey>? TcpConnectEstablished;
    event Action<FlowKey>? TcpConnectClosed;

    event Action<IPAddress, ushort>? UdpBindAdded;
    event Action<IPAddress, ushort>? UdpBindRemoved;

    /// <summary>Process ids currently in scope.</summary>
    IReadOnlyCollection<uint> TrackedProcessIds { get; }

    /// <summary>The TCP flows in scope right now. A snapshot for diagnostics, not a live view.</summary>
    IReadOnlyCollection<FlowKey> TcpSnapshot { get; }

    void Start();

    /// <summary>
    /// Brings another process into scope: opens a SOCKET handle for it and pre-populates the
    /// sockets it already has. Idempotent.
    /// </summary>
    void AddProcess(uint pid);

    /// <summary>
    /// Drops a process from scope and forgets its flows, so its next packets pass through
    /// untouched. False when the pid was not tracked.
    /// </summary>
    bool RemoveProcess(uint pid);

    bool IsTrackedProcess(uint pid);

    bool IsTrackedTcp(FlowKey key);
    bool IsTrackedUdp(IPAddress localAddr, ushort localPort);

    /// <summary>Owner of a tracked TCP flow. False when the flow is unknown.</summary>
    bool TryGetTcpProcessId(FlowKey key, out uint processId);

    /// <summary>
    /// Owner of a tracked UDP bind. A bind on ANY (0.0.0.0 / ::) accepts any source address at
    /// that port, so it is checked as a fallback.
    /// </summary>
    bool TryGetUdpProcessId(IPAddress localAddr, ushort localPort, out uint processId);

    /// <summary>
    /// Snapshots the kernel's TCP/UDP tables for every tracked pid and adds anything new. Called
    /// by the NAT stage when an egress packet matches no known flow — this is what closes the race
    /// where the SYN reaches the NETWORK layer before the SOCKET event was processed.
    /// Throttled unless <paramref name="force"/> says otherwise (a SYN forces it: the answer
    /// decides whether a brand-new connection is captured or lost for its whole lifetime).
    /// </summary>
    bool TryReconcileFromKernel(out int tcpAdded, out int udpAdded, bool force = false);
}
