using System;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace TqkLibrary.WinDivert.Flow.Models;

/// <summary>
/// An IP address as two integers: comparable, hashable and buildable from a packet's bytes without
/// allocating an <see cref="IPAddress"/>. IPv4 lives in <see cref="Lo"/> (so 0.0.0.0 is
/// Family 4 / 0 / 0, distinct from ::), and an IPv4-mapped IPv6 address stays Family 6.
/// </summary>
public readonly struct IpAddressKey : IEquatable<IpAddressKey>
{
    public static readonly IpAddressKey Any4 = new IpAddressKey(4, 0, 0);
    public static readonly IpAddressKey Any6 = new IpAddressKey(6, 0, 0);

    public ulong Hi { get; }
    public ulong Lo { get; }
    /// <summary>4 or 6.</summary>
    public byte Family { get; }

    private IpAddressKey(byte family, ulong hi, ulong lo)
    {
        Family = family;
        Hi = hi;
        Lo = lo;
    }

    /// <param name="bytes">The 4 address bytes, network order.</param>
    public static IpAddressKey FromIPv4(ReadOnlySpan<byte> bytes)
        => new IpAddressKey(4, 0, BinaryPrimitives.ReadUInt32BigEndian(bytes));

    /// <param name="bytes">The 16 address bytes, network order.</param>
    public static IpAddressKey FromIPv6(ReadOnlySpan<byte> bytes)
        => new IpAddressKey(6, BinaryPrimitives.ReadUInt64BigEndian(bytes), BinaryPrimitives.ReadUInt64BigEndian(bytes.Slice(8)));

    public static IpAddressKey FromIPAddress(IPAddress address)
    {
        if (address is null) throw new ArgumentNullException(nameof(address));
        Span<byte> bytes = stackalloc byte[16];
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            address.TryWriteBytes(bytes, out _);
            return FromIPv4(bytes.Slice(0, 4));
        }
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            address.TryWriteBytes(bytes, out _);
            return FromIPv6(bytes);
        }
        throw new ArgumentException($"Unsupported address family {address.AddressFamily}.", nameof(address));
    }

    public IPAddress ToIPAddress()
    {
        Span<byte> bytes = stackalloc byte[16];
        if (Family == 4)
        {
            BinaryPrimitives.WriteUInt32BigEndian(bytes, (uint)Lo);
            return new IPAddress(bytes.Slice(0, 4));
        }
        BinaryPrimitives.WriteUInt64BigEndian(bytes, Hi);
        BinaryPrimitives.WriteUInt64BigEndian(bytes.Slice(8), Lo);
        return new IPAddress(bytes);
    }

    public bool Equals(IpAddressKey other) => Family == other.Family && Hi == other.Hi && Lo == other.Lo;
    public override bool Equals(object? obj) => obj is IpAddressKey k && Equals(k);
    public override int GetHashCode() => HashCode.Combine(Family, Hi, Lo);

    public static bool operator ==(IpAddressKey left, IpAddressKey right) => left.Equals(right);
    public static bool operator !=(IpAddressKey left, IpAddressKey right) => !left.Equals(right);

    public override string ToString() => ToIPAddress().ToString();
}
