using System;
using System.Net;

namespace TqkLibrary.WinDivert.Flow.Models;

internal readonly struct UdpBindKey : IEquatable<UdpBindKey>
{
    public IPAddress Address { get; }
    public ushort Port { get; }

    public UdpBindKey(IPAddress address, ushort port)
    {
        Address = address;
        Port = port;
    }

    public bool Equals(UdpBindKey other) => Port == other.Port && Equals(Address, other.Address);
    public override bool Equals(object? obj) => obj is UdpBindKey k && Equals(k);
    public override int GetHashCode() => (Address?.GetHashCode() ?? 0) ^ Port;
}
