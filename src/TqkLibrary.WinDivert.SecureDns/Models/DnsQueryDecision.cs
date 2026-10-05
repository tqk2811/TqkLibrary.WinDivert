using System;

namespace TqkLibrary.WinDivert.SecureDns.Models;

/// <summary>
/// What a <see cref="DnsQueryDecider"/> wants done with one query: let it go out untouched, or
/// answer it over a given resolver.
/// </summary>
public readonly struct DnsQueryDecision
{
    /// <summary>Let the query through to the OS resolver's real server, untouched.</summary>
    public static DnsQueryDecision Pass => default;

    /// <summary>Null means <see cref="Pass"/>.</summary>
    public IDnsResolver? Resolver { get; }

    /// <summary>
    /// When the lookup fails (exception, timeout, empty answer) or the backlog is full, send the
    /// ORIGINAL query out to its real server instead of answering SERVFAIL.
    /// The fallback re-injects the original packet straight to the network, bypassing every later
    /// middleware (NAT/UDP relay, <c>BlockUnhandledTargetUdp</c>). It is a deliberate plain-DNS leak
    /// that the caller opts into by setting this flag.
    /// </summary>
    public bool FallbackToPlainDnsOnFailure { get; }

    public bool IsPass => Resolver == null;

    private DnsQueryDecision(IDnsResolver resolver, bool fallbackToPlainDnsOnFailure)
    {
        Resolver = resolver;
        FallbackToPlainDnsOnFailure = fallbackToPlainDnsOnFailure;
    }

    /// <summary>Answer the query over <paramref name="resolver"/>, which the caller keeps owning.</summary>
    public static DnsQueryDecision Resolve(IDnsResolver resolver, bool fallbackToPlainDnsOnFailure)
        => new DnsQueryDecision(resolver ?? throw new ArgumentNullException(nameof(resolver)), fallbackToPlainDnsOnFailure);
}
