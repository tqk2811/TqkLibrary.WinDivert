using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;

namespace TqkLibrary.WinDivert.SecureDns;

// IP -> domain learned from the DNS answers the tracked processes received. This is what lets a
// routing rule say "*.google.com goes through the proxy" even for a connection that carries no
// SNI and no Host header: the destination IP is looked up here.
//
// Entries keep the record's TTL as a hint but are NOT dropped the moment it expires — a name once
// seen for an IP stays resolvable for ExpiredRetention afterwards, because a long-lived connection
// (or a log line written later) still refers to the same host. IsFresh tells the two apart.
public sealed class ReverseDnsTable
{
    private readonly ConcurrentDictionary<IPAddress, Entry> _entries = new();

    // How long an expired mapping is still answered before it is dropped entirely.
    private readonly TimeSpan _expiredRetention;
    // Hard cap so a process resolving endlessly can't grow this without bound.
    private readonly int _capacity;

    public ReverseDnsTable(TimeSpan? expiredRetention = null, int capacity = 20_000)
    {
        _expiredRetention = expiredRetention ?? TimeSpan.FromMinutes(30);
        _capacity = capacity < 1 ? 1 : capacity;
    }

    public int Count => _entries.Count;

    // Records one answer. A name learned later wins: DNS round-robin and CDN re-resolution mean
    // the freshest answer is the one that describes the connection about to be made.
    public void Add(IPAddress address, string name, TimeSpan ttl)
    {
        if (address is null || string.IsNullOrEmpty(name)) return;
        DateTime now = DateTime.UtcNow;
        // A zero TTL still deserves a usable window — the connection it was resolved for is
        // opening right now.
        TimeSpan effective = ttl < TimeSpan.FromSeconds(30) ? TimeSpan.FromSeconds(30) : ttl;
        _entries[address] = new Entry(name, now + effective);

        if (_entries.Count > _capacity) Trim(now);
    }

    public void AddRange(IEnumerable<DnsAddressRecord> records)
    {
        if (records is null) return;
        foreach (DnsAddressRecord r in records)
            Add(r.Address, r.QuestionName, r.Ttl);
    }

    // The domain last seen for this IP, or null when nothing was learned (or it aged out).
    public string? Resolve(IPAddress address)
    {
        if (address is null) return null;
        if (!_entries.TryGetValue(address, out Entry? entry)) return null;
        if (DateTime.UtcNow > entry.ExpiresUtc + _expiredRetention)
        {
            _entries.TryRemove(address, out _);
            return null;
        }
        return entry.Name;
    }

    // True when the mapping is still within its DNS TTL.
    public bool IsFresh(IPAddress address)
        => address != null
           && _entries.TryGetValue(address, out Entry? entry)
           && DateTime.UtcNow <= entry.ExpiresUtc;

    public void Clear() => _entries.Clear();

    private void Trim(DateTime now)
    {
        // Drop everything already past retention first; if that isn't enough, drop the entries
        // closest to expiry.
        foreach (var kv in _entries)
        {
            if (now > kv.Value.ExpiresUtc + _expiredRetention)
                _entries.TryRemove(kv.Key, out _);
        }
        if (_entries.Count <= _capacity) return;

        var byExpiry = new List<KeyValuePair<IPAddress, Entry>>(_entries);
        byExpiry.Sort((a, b) => a.Value.ExpiresUtc.CompareTo(b.Value.ExpiresUtc));
        int toDrop = _entries.Count - _capacity;
        for (int i = 0; i < toDrop && i < byExpiry.Count; i++)
            _entries.TryRemove(byExpiry[i].Key, out _);
    }

    private sealed class Entry
    {
        public string Name { get; }
        public DateTime ExpiresUtc { get; }

        public Entry(string name, DateTime expiresUtc)
        {
            Name = name;
            ExpiresUtc = expiresUtc;
        }
    }
}
