using System;
using System.Collections.Concurrent;
using System.Net;

namespace TqkLibrary.WinDivert.Redirect;

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

    public IPEndPoint OriginalDestination => new IPEndPoint(OriginalDestinationAddress, OriginalDestinationPort);
    public IPEndPoint OriginalSource => new IPEndPoint(OriginalSourceAddress, OriginalSourcePort);
}

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

// Keyed by (protocol, origSrcPort). Safe within one target PID since src ports are unique
// per flow for that PID; the relay uses srcPort as the identifier to recover the original destination.
public sealed class NatTable
{
    private readonly ConcurrentDictionary<NatKey, NatEntry> _entries = new();

    public void Upsert(NatEntry entry)
        => _entries[new NatKey(entry.Protocol, entry.OriginalSourcePort)] = entry;

    public NatEntry? Find(byte protocol, ushort srcPort)
        => _entries.TryGetValue(new NatKey(protocol, srcPort), out var e) ? e : null;

    public bool Remove(byte protocol, ushort srcPort)
        => _entries.TryRemove(new NatKey(protocol, srcPort), out _);

    public int Count => _entries.Count;
}
