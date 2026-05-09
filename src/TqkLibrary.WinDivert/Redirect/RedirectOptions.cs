using System;
using System.Threading;
using System.Threading.Tasks;

namespace TqkLibrary.WinDivert.Redirect;

[Flags]
public enum RedirectProtocol
{
    None = 0,
    Tcp = 1,
    Udp = 2,
    All = Tcp | Udp,
}

public delegate Task TcpConnectionHandler(RedirectedTcpConnection connection, CancellationToken ct);

// Called for each outbound UDP datagram. Return the (possibly rewritten) payload to forward
// to the original destination, or null to drop. Incoming replies are delivered to the process
// unchanged; to modify replies, set ReplyHandler.
public delegate byte[]? UdpDatagramHandler(RedirectedUdpDatagram datagram, CancellationToken ct);

public sealed class RedirectOptions
{
    public uint ProcessId { get; set; }
    public RedirectProtocol Protocols { get; set; } = RedirectProtocol.Tcp;

    // If null, RedirectedTcpConnection.RelayAsync() is called for a default pass-through pipe.
    public TcpConnectionHandler? TcpConnectionHandler { get; set; }

    // If null, UDP datagrams are forwarded unchanged.
    public UdpDatagramHandler? UdpDatagramHandler { get; set; }

    // Applied to the WinDivert NETWORK handle priority (-30000..30000; higher = earlier).
    public short NetworkPriority { get; set; } = 100;
    public short SocketPriority { get; set; } = 100;

    // If set, every captured packet, redirect, NAT entry, and socket event is appended to this
    // file with a UTC timestamp. Null disables diagnostic logging (no overhead).
    public string? LogFilePath { get; set; }
}
