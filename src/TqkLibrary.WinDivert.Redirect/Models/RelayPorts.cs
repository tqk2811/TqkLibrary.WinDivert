namespace TqkLibrary.WinDivert.Redirect.Models;

/// <summary>
/// The loopback ports a redirected packet can be sent to, one per protocol and address family.
/// Zero means "no relay listening for that combination", which the NAT stage reads as "leave these
/// packets to the rest of the pipeline".
/// </summary>
/// <remarks>
/// The two families need separate ports because they are separate listeners: a dual-mode socket
/// would have to bind [::], exposing the relay to the LAN, so loopback-only costs a second socket.
/// </remarks>
public readonly struct RelayPorts
{
    public int Tcp { get; }
    public int Udp { get; }
    public int TcpV6 { get; }
    public int UdpV6 { get; }

    public RelayPorts(int tcp, int udp, int tcpV6 = 0, int udpV6 = 0)
    {
        Tcp = tcp;
        Udp = udp;
        TcpV6 = tcpV6;
        UdpV6 = udpV6;
    }

    /// <summary>The port a packet of this protocol and family belongs on, or 0 when there is none.</summary>
    public int For(bool isTcp, bool isIpv6)
        => isTcp ? (isIpv6 ? TcpV6 : Tcp) : (isIpv6 ? UdpV6 : Udp);

    /// <summary>Only the IPv4 pair — for a pipeline that does not redirect IPv6.</summary>
    public static RelayPorts Ipv4Only(int tcp, int udp) => new RelayPorts(tcp, udp);

    /// <summary>Only the IPv6 pair — for the parallel IPv6 pipeline.</summary>
    public static RelayPorts Ipv6Only(int tcpV6, int udpV6) => new RelayPorts(0, 0, tcpV6, udpV6);

    public override string ToString() => $"tcp={Tcp} udp={Udp} tcpV6={TcpV6} udpV6={UdpV6}";
}
