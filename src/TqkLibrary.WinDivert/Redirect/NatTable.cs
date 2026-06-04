using System.Collections.Concurrent;

namespace TqkLibrary.WinDivert.Redirect;

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
