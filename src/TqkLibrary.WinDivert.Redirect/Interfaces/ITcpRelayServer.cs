using System;

namespace TqkLibrary.WinDivert.Redirect.Interfaces;

/// <summary>
/// The loopback listener that redirected TCP connections actually land on. Whatever connects here
/// is the target process, arriving through a rewritten packet, and the NAT table says where it
/// meant to go.
/// </summary>
public interface ITcpRelayServer : IDisposable
{
    /// <summary>Loopback port of the IPv4 listener.</summary>
    int Port { get; }

    /// <summary>Loopback port of the IPv6 listener; 0 when IPv6 redirect is off or unavailable.</summary>
    int PortV6 { get; }

    /// <summary>
    /// Raised when a redirected connection is accepted / finished. The connection carries the pid,
    /// the original destination and live byte counters, so a UI can bind straight to it. Handlers
    /// run on the relay task — keep them short.
    /// </summary>
    event Action<RedirectedTcpConnection>? ConnectionOpened;
    event Action<RedirectedTcpConnection>? ConnectionClosed;

    void Start();
}
