using System.Collections.Concurrent;

namespace TqkLibrary.WinDivert.Redirect;

// Keyed by (protocol, address family, origSrcPort) — no pid in the key, on purpose.
//
// The assumption this rests on: Windows hands out a source port that is unique MACHINE-WIDE for a
// given protocol AND address family, so two processes can never hold the same key at the same
// moment. That is what makes it safe even when the redirector tracks many pids: the relay only
// knows the source port of the loopback connection it accepted plus which of its two listeners
// (IPv4 / IPv6) accepted it, and that pair identifies exactly one flow. The owning pid is carried
// in the value (NatEntry.ProcessId), not in the key.
//
// An entry is overwritten when the OS recycles a source port for a new flow, which is the correct
// behaviour — the old flow is gone by then.
public sealed class NatTable : INatTable
{
    private readonly ConcurrentDictionary<NatKey, NatEntry> _entries = new();

    // Returns true when this is a flow the table had not seen — a brand-new source port, or a
    // recycled one now going somewhere else. Callers use it to do the per-flow work (logging, the
    // reverse name lookup) exactly once instead of on every packet of the flow, which is where the
    // cost of that work actually lands.
    public bool Upsert(NatEntry entry)
    {
        var key = new NatKey(entry.Protocol, entry.OriginalSourcePort, entry.IsIpv6);
        bool isNew = !_entries.TryGetValue(key, out NatEntry? previous)
            || previous.OriginalDestinationPort != entry.OriginalDestinationPort
            || !previous.OriginalDestinationAddress.Equals(entry.OriginalDestinationAddress);
        _entries[key] = entry;
        return isNew;
    }

    public NatEntry? Find(byte protocol, ushort srcPort, bool isIpv6)
        => _entries.TryGetValue(new NatKey(protocol, srcPort, isIpv6), out var e) ? e : null;

    public bool Remove(byte protocol, ushort srcPort, bool isIpv6)
        => _entries.TryRemove(new NatKey(protocol, srcPort, isIpv6), out _);

    public int Count => _entries.Count;
}
