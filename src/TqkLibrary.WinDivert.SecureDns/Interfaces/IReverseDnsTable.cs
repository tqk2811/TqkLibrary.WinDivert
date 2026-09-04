using System;
using System.Collections.Generic;
using System.Net;

namespace TqkLibrary.WinDivert.SecureDns.Interfaces;

/// <summary>
/// IP to domain, learned from the DNS answers that crossed the wire. This is what lets a routing
/// rule say "*.example.com goes through the proxy" even for a connection that carries no SNI and
/// no Host header: the destination address is looked up here.
/// </summary>
public interface IReverseDnsTable
{
    int Count { get; }

    /// <summary>
    /// Records one answer. A name learned later wins — DNS round-robin and CDN re-resolution mean
    /// the freshest answer is the one describing the connection about to be made.
    /// </summary>
    void Add(IPAddress address, string name, TimeSpan ttl);

    void AddRange(IEnumerable<DnsAddressRecord> records);

    /// <summary>The domain last seen for this IP, or null when nothing was learned (or it aged out).</summary>
    string? Resolve(IPAddress address);

    /// <summary>
    /// True while the mapping is still within its DNS TTL. A mapping that is past it is still
    /// answered by <see cref="Resolve"/> for a while — a long-lived connection refers to the same
    /// host no matter what the TTL says — but a caller that needs certainty can ask.
    /// </summary>
    bool IsFresh(IPAddress address);

    void Clear();
}
