using System;

namespace TqkLibrary.WinDivert.Redirect.Models;

internal readonly struct NatKey : IEquatable<NatKey>
{
    public byte Protocol { get; }
    public ushort SourcePort { get; }
    // IPv4 and IPv6 have SEPARATE port spaces on Windows: one socket may hold TCP/50000 over IPv4
    // while another holds TCP/50000 over IPv6 at the same moment. Without the family in the key the
    // two flows would overwrite each other's NAT entry and the relay would send one of them to the
    // wrong destination.
    public bool IsIpv6 { get; }

    public NatKey(byte protocol, ushort port, bool isIpv6)
    {
        Protocol = protocol;
        SourcePort = port;
        IsIpv6 = isIpv6;
    }

    public bool Equals(NatKey other)
        => Protocol == other.Protocol && SourcePort == other.SourcePort && IsIpv6 == other.IsIpv6;
    public override bool Equals(object? obj) => obj is NatKey k && Equals(k);
    public override int GetHashCode() => (Protocol << 17) | (IsIpv6 ? 1 << 16 : 0) | SourcePort;
}
