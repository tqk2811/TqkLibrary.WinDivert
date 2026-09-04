using System.Collections.Generic;

namespace TqkLibrary.WinDivert.SecureDns.Interfaces;

/// <summary>
/// Reads the address answers (A / AAAA) out of a DNS message. The wire format is the same whether
/// the message arrived over UDP/53 or inside a DoH response, so one parser serves both.
/// </summary>
public interface IDnsMessageParser
{
    /// <summary>
    /// Returns the A/AAAA answers, or an empty list when the message carries none or is malformed.
    /// Never throws on bad input: a packet off the wire is not trustworthy by construction.
    /// </summary>
    IReadOnlyList<DnsAddressRecord> ParseAddressAnswers(byte[] wire, int offset, int length);
}
