using System;
using System.Net;

namespace TqkLibrary.WinDivert.Flow;

public readonly struct FlowKey : IEquatable<FlowKey>
{
    public byte Protocol { get; }
    public IPAddress LocalAddress { get; }
    public ushort LocalPort { get; }
    public IPAddress RemoteAddress { get; }
    public ushort RemotePort { get; }

    public FlowKey(byte protocol, IPAddress localAddr, ushort localPort, IPAddress remoteAddr, ushort remotePort)
    {
        Protocol = protocol;
        LocalAddress = localAddr;
        LocalPort = localPort;
        RemoteAddress = remoteAddr;
        RemotePort = remotePort;
    }

    public bool Equals(FlowKey other) =>
        Protocol == other.Protocol &&
        LocalPort == other.LocalPort &&
        RemotePort == other.RemotePort &&
        Equals(LocalAddress, other.LocalAddress) &&
        Equals(RemoteAddress, other.RemoteAddress);

    public override bool Equals(object? obj) => obj is FlowKey k && Equals(k);

    public override int GetHashCode()
    {
        unchecked
        {
            int h = Protocol;
            h = (h * 397) ^ LocalPort;
            h = (h * 397) ^ RemotePort;
            h = (h * 397) ^ (LocalAddress?.GetHashCode() ?? 0);
            h = (h * 397) ^ (RemoteAddress?.GetHashCode() ?? 0);
            return h;
        }
    }

    public override string ToString() => $"{(Protocol == 6 ? "tcp" : Protocol == 17 ? "udp" : Protocol.ToString())} {LocalAddress}:{LocalPort} -> {RemoteAddress}:{RemotePort}";
}
