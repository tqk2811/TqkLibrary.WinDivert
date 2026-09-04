using System;
using System.Net;

namespace TqkLibrary.WinDivert.Redirect.Models;

public sealed class NatEntry
{
    public uint ProcessId { get; }
    public byte Protocol { get; }
    public IPAddress OriginalSourceAddress { get; }
    public ushort OriginalSourcePort { get; }
    public IPAddress OriginalDestinationAddress { get; }
    public ushort OriginalDestinationPort { get; }
    // IfIdx/SubIfIdx of the real network interface the original packet was sent on.
    // Needed when reinjecting the relay's reply as inbound on that same interface so the
    // target process's socket can receive it.
    public uint IfIdx { get; }
    public uint SubIfIdx { get; }
    public DateTime CreatedUtc { get; }

    public NatEntry(uint pid, byte protocol, IPAddress origSrc, ushort origSrcPort, IPAddress origDst, ushort origDstPort, uint ifIdx, uint subIfIdx)
    {
        ProcessId = pid;
        Protocol = protocol;
        OriginalSourceAddress = origSrc;
        OriginalSourcePort = origSrcPort;
        OriginalDestinationAddress = origDst;
        OriginalDestinationPort = origDstPort;
        IfIdx = ifIdx;
        SubIfIdx = subIfIdx;
        CreatedUtc = DateTime.UtcNow;
    }

    /// <summary>
    /// True when the flow this entry describes is IPv6. Part of the NatTable key, because the two
    /// families have independent port spaces.
    /// </summary>
    public bool IsIpv6 => OriginalSourceAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;

    public IPEndPoint OriginalDestination => new IPEndPoint(OriginalDestinationAddress, OriginalDestinationPort);
    public IPEndPoint OriginalSource => new IPEndPoint(OriginalSourceAddress, OriginalSourcePort);
}
