using System;

namespace TqkLibrary.WinDivert.Redirect.Models;

internal readonly struct NatKey : IEquatable<NatKey>
{
    public byte Protocol { get; }
    public ushort SourcePort { get; }

    public NatKey(byte protocol, ushort port)
    {
        Protocol = protocol;
        SourcePort = port;
    }

    public bool Equals(NatKey other) => Protocol == other.Protocol && SourcePort == other.SourcePort;
    public override bool Equals(object? obj) => obj is NatKey k && Equals(k);
    public override int GetHashCode() => (Protocol << 16) | SourcePort;
}
