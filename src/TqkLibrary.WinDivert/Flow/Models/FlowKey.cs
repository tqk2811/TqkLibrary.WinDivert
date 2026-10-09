using System;
using System.Net;

namespace TqkLibrary.WinDivert.Flow.Models;

public readonly struct FlowKey : IEquatable<FlowKey>
{
    // Identity is the keys; the IPAddress objects only exist so callers that built one get the same
    // instance back instead of a fresh allocation.
    private readonly IpAddressKey _local;
    private readonly IpAddressKey _remote;
    private readonly IPAddress? _localObj;
    private readonly IPAddress? _remoteObj;

    public byte Protocol { get; }
    public IPAddress LocalAddress => _localObj ?? _local.ToIPAddress();
    public ushort LocalPort { get; }
    public IPAddress RemoteAddress => _remoteObj ?? _remote.ToIPAddress();
    public ushort RemotePort { get; }
    public IpAddressKey LocalKey => _local;
    public IpAddressKey RemoteKey => _remote;

    public FlowKey(byte protocol, IPAddress localAddr, ushort localPort, IPAddress remoteAddr, ushort remotePort)
    {
        Protocol = protocol;
        _localObj = localAddr;
        _local = IpAddressKey.FromIPAddress(localAddr);
        LocalPort = localPort;
        _remoteObj = remoteAddr;
        _remote = IpAddressKey.FromIPAddress(remoteAddr);
        RemotePort = remotePort;
    }

    /// <summary>Allocation-free: the addresses stay as keys until someone asks for an <see cref="IPAddress"/>.</summary>
    public FlowKey(byte protocol, in IpAddressKey local, ushort localPort, in IpAddressKey remote, ushort remotePort)
    {
        Protocol = protocol;
        _local = local;
        _localObj = null;
        LocalPort = localPort;
        _remote = remote;
        _remoteObj = null;
        RemotePort = remotePort;
    }

    public bool Equals(FlowKey other) =>
        Protocol == other.Protocol &&
        LocalPort == other.LocalPort &&
        RemotePort == other.RemotePort &&
        _local.Equals(other._local) &&
        _remote.Equals(other._remote);

    public override bool Equals(object? obj) => obj is FlowKey k && Equals(k);

    public override int GetHashCode() => HashCode.Combine(Protocol, LocalPort, RemotePort, _local, _remote);

    public override string ToString() => $"{(Protocol == 6 ? "tcp" : Protocol == 17 ? "udp" : Protocol.ToString())} {_local}:{LocalPort} -> {_remote}:{RemotePort}";
}
