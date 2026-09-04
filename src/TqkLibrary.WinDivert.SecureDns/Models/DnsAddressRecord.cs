using System;
using System.Net;

namespace TqkLibrary.WinDivert.SecureDns.Models;

// One address answer (A or AAAA) taken out of a DNS response.
//
// OwnerName is the name that literally owns the record, which for a CDN is usually the tail of a
// CNAME chain (e.g. "e1234.dscb.akamaiedge.net"). QuestionName is what the process actually asked
// for ("www.example.com") — that is the name a routing rule should match, so both are kept.
public sealed class DnsAddressRecord
{
    public string OwnerName { get; }
    public string QuestionName { get; }
    public IPAddress Address { get; }
    public TimeSpan Ttl { get; }

    public DnsAddressRecord(string ownerName, string questionName, IPAddress address, TimeSpan ttl)
    {
        OwnerName = ownerName;
        QuestionName = questionName;
        Address = address ?? throw new ArgumentNullException(nameof(address));
        Ttl = ttl;
    }

    public override string ToString() => $"{QuestionName} -> {Address} (ttl {Ttl.TotalSeconds:F0}s)";
}
