namespace TqkLibrary.WinDivert.SecureDns.Models;

/// <summary>
/// One intercepted DNS query, as handed to a <see cref="DnsQueryDecider"/> on the pump thread.
/// </summary>
public readonly struct DnsQueryInfo
{
    /// <summary>Owner of the asking UDP socket, or null when the socket tracker does not know it.</summary>
    public uint? ProcessId { get; }

    /// <summary>The first question's name: lower-case, no trailing dot.</summary>
    public string QueryName { get; }

    /// <summary>The first question's QTYPE (1 = A, 28 = AAAA, 65 = HTTPS, ...).</summary>
    public ushort QueryType { get; }

    /// <summary>True when the query travelled over IPv6.</summary>
    public bool IsIpv6 { get; }

    public DnsQueryInfo(uint? processId, string queryName, ushort queryType, bool isIpv6)
    {
        ProcessId = processId;
        QueryName = queryName ?? string.Empty;
        QueryType = queryType;
        IsIpv6 = isIpv6;
    }

    public override string ToString() => $"{QueryName} type={QueryType} pid={ProcessId?.ToString() ?? "?"}";
}
