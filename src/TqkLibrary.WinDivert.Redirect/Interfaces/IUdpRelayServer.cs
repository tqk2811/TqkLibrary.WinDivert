using System;
using System.Threading.Tasks;

namespace TqkLibrary.WinDivert.Redirect.Interfaces;

/// <summary>
/// The loopback listener redirected UDP datagrams land on, plus the upstream sockets that carry
/// them onwards — one per (original source port, address family).
/// </summary>
public interface IUdpRelayServer : IDisposable
{
    /// <summary>Loopback port of the IPv4 listener.</summary>
    int Port { get; }

    /// <summary>Loopback port of the IPv6 listener; 0 when IPv6 redirect is off or unavailable.</summary>
    int PortV6 { get; }

    void Start();

    /// <summary>
    /// Delivers a datagram to the target process as if it came from the original destination. For
    /// a handler that took over UDP forwarding itself (SOCKS5 UDP ASSOCIATE, say) and so receives
    /// replies the relay upstream socket never sees.
    /// </summary>
    /// <param name="isIpv6">
    /// Selects which loopback listener the reply leaves from. It MUST match the family of the
    /// flow, or the NAT stage will not recognise the packet and the process will never see it.
    /// </param>
    Task InjectReplyToProcessAsync(ushort processClientPort, byte[] payload, bool isIpv6 = false);
}
