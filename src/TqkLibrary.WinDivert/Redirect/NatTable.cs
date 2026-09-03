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
public sealed class NatTable
{
    private readonly ConcurrentDictionary<NatKey, NatEntry> _entries = new();

    public void Upsert(NatEntry entry)
        => _entries[new NatKey(entry.Protocol, entry.OriginalSourcePort, entry.IsIpv6)] = entry;

    public NatEntry? Find(byte protocol, ushort srcPort, bool isIpv6)
        => _entries.TryGetValue(new NatKey(protocol, srcPort, isIpv6), out var e) ? e : null;

    public bool Remove(byte protocol, ushort srcPort, bool isIpv6)
        => _entries.TryRemove(new NatKey(protocol, srcPort, isIpv6), out _);

    public int Count => _entries.Count;
}
