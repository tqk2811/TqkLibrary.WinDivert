using System;
using System.Collections.Concurrent;
using System.Threading;

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
// behaviour — the old flow is gone by then. Overwriting alone is not enough, though: it only
// happens if we see the new flow's first packet. Miss that SYN and the recycled port still answers
// with the old flow's destination, which sends a live connection through a NAT it never asked for
// and hides it from the escaped-flow check that would otherwise have reset it. So entries also
// expire: a flow the tracker reports closed stays findable for the grace window the kernel spends
// retransmitting its trailing FIN-ACK, and no longer.
public sealed class NatTable : INatTable
{
    /// <summary>
    /// How long a closed flow's entry stays findable. The socket is gone, but the kernel keeps
    /// retransmitting the trailing FIN-ACK or RST-ACK for a while and those still need translating;
    /// the socket tracker lingers closed flows for the same span for the same reason.
    /// </summary>
    private const int CloseGraceMs = 30_000;

    /// <summary>Shortest gap between sweeps, so a burst of closes does not walk the table each time.</summary>
    private const int SweepIntervalMs = 5_000;

    private readonly ConcurrentDictionary<NatKey, Slot> _entries = new();
    private long _nextSweepTicks = Environment.TickCount64 + SweepIntervalMs;

    // Returns true when this is a flow the table had not seen — a brand-new source port, or a
    // recycled one now going somewhere else. Callers use it to do the per-flow work (logging, the
    // reverse name lookup) exactly once instead of on every packet of the flow, which is where the
    // cost of that work actually lands.
    public bool Upsert(NatEntry entry)
    {
        var key = new NatKey(entry.Protocol, entry.OriginalSourcePort, entry.IsIpv6);
        bool isNew = !_entries.TryGetValue(key, out Slot? previous)
            || previous.IsExpired
            || previous.Entry.OriginalDestinationPort != entry.OriginalDestinationPort
            || !previous.Entry.OriginalDestinationAddress.Equals(entry.OriginalDestinationAddress);
        _entries[key] = new Slot(entry);
        return isNew;
    }

    public NatEntry? Find(byte protocol, ushort srcPort, bool isIpv6)
    {
        var key = new NatKey(protocol, srcPort, isIpv6);
        if (!_entries.TryGetValue(key, out Slot? slot)) return null;

        // Correctness does not wait on the sweep: past its grace an entry must not answer for
        // whatever flow holds that port now.
        if (slot.IsExpired)
        {
            _entries.TryRemove(key, out _);
            return null;
        }
        return slot.Entry;
    }

    public bool Remove(byte protocol, ushort srcPort, bool isIpv6)
        => _entries.TryRemove(new NatKey(protocol, srcPort, isIpv6), out _);

    public void MarkClosed(byte protocol, ushort srcPort, bool isIpv6)
    {
        if (_entries.TryGetValue(new NatKey(protocol, srcPort, isIpv6), out Slot? slot))
            slot.ExpireAt(Environment.TickCount64 + CloseGraceMs);

        SweepIfDue();
    }

    public int Count => _entries.Count;

    /// <summary>
    /// Drops entries whose grace has run out. Driven by close events rather than a timer of its
    /// own: closes are exactly when the table gains something to forget, and the interval gate
    /// keeps a burst of them from walking the whole table repeatedly.
    /// </summary>
    private void SweepIfDue()
    {
        long now = Environment.TickCount64;
        long due = Interlocked.Read(ref _nextSweepTicks);
        if (now < due) return;
        if (Interlocked.CompareExchange(ref _nextSweepTicks, now + SweepIntervalMs, due) != due) return;

        foreach (var kv in _entries)
        {
            if (kv.Value.IsExpired) _entries.TryRemove(kv.Key, out _);
        }
    }

    /// <summary>One entry plus when it stops being usable. Mutable so a close can date an entry
    /// without replacing it and losing a concurrent Upsert.</summary>
    private sealed class Slot
    {
        private long _expireAtTicks;

        public Slot(NatEntry entry)
        {
            Entry = entry;
        }

        public NatEntry Entry { get; }

        public void ExpireAt(long ticks) => Interlocked.Exchange(ref _expireAtTicks, ticks);

        /// <summary>Zero means the flow is still open, and TickCount64 never returns to zero.</summary>
        public bool IsExpired
        {
            get
            {
                long at = Interlocked.Read(ref _expireAtTicks);
                return at != 0 && Environment.TickCount64 >= at;
            }
        }
    }
}
