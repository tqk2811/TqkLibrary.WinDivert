namespace TqkLibrary.WinDivert.SecureDns;

/// <summary>
/// Picks, per intercepted DNS query, whether and through which resolver it is answered over DoH.
/// Runs on the capture pump thread for every query, so it must be fast and must not block.
/// </summary>
public delegate DnsQueryDecision DnsQueryDecider(in DnsQueryInfo query);
