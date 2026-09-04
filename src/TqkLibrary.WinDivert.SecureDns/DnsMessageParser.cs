using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace TqkLibrary.WinDivert.SecureDns;

// Minimal read-only parser for DNS responses (RFC 1035 wire format), enough to learn IP -> name
// mappings. It never builds a message and never throws on malformed input: a truncated or
// nonsense packet simply yields no records.
//
// Only A and AAAA answers are returned. CNAME records are followed inside the message so the
// address ends up attributed to the name the process actually asked for.
public sealed class DnsMessageParser : IDnsMessageParser
{
    private const int HeaderLength = 12;
    private const ushort TypeA = 1;
    private const ushort TypeCname = 5;
    private const ushort TypeAaaa = 28;
    private const ushort ClassIn = 1;
    // Guards against a compression-pointer loop; no legal name has this many labels.
    private const int MaxNameJumps = 64;

    // Parses a DNS response. Returns an empty list for queries, errors, and malformed data.
    public IReadOnlyList<DnsAddressRecord> ParseAddressAnswers(byte[] wire, int offset, int length)
    {
        var empty = Array.Empty<DnsAddressRecord>();
        if (wire == null || length < HeaderLength || offset < 0 || offset + length > wire.Length) return empty;

        int end = offset + length;
        int pos = offset;

        ushort flags = ReadUInt16(wire, pos + 2);
        bool isResponse = (flags & 0x8000) != 0;
        int rcode = flags & 0x000F;
        if (!isResponse || rcode != 0) return empty;

        int questionCount = ReadUInt16(wire, pos + 4);
        int answerCount = ReadUInt16(wire, pos + 6);
        if (answerCount == 0) return empty;

        pos += HeaderLength;

        // ---- questions: only the first name matters (a query carries exactly one in practice) ----
        string questionName = string.Empty;
        for (int i = 0; i < questionCount; i++)
        {
            if (!TryReadName(wire, offset, end, ref pos, out string name)) return empty;
            if (i == 0) questionName = name;
            if (pos + 4 > end) return empty;
            pos += 4; // QTYPE + QCLASS
        }

        // ---- answers ----
        var records = new List<DnsAddressRecord>(answerCount);
        // owner name -> the question name it ultimately answers, extended as CNAMEs are walked.
        var aliasOf = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (questionName.Length > 0) aliasOf[questionName] = questionName;

        for (int i = 0; i < answerCount; i++)
        {
            if (!TryReadName(wire, offset, end, ref pos, out string owner)) break;
            if (pos + 10 > end) break;

            ushort type = ReadUInt16(wire, pos);
            ushort klass = ReadUInt16(wire, pos + 2);
            uint ttlSeconds = ReadUInt32(wire, pos + 4);
            int rdLength = ReadUInt16(wire, pos + 8);
            pos += 10;
            if (rdLength < 0 || pos + rdLength > end) break;

            int rdataStart = pos;
            pos += rdLength;

            if (klass != ClassIn) continue;

            // The question this owner name answers; unknown owners stand for themselves.
            string attributedTo = aliasOf.TryGetValue(owner, out string? q) ? q : owner;

            switch (type)
            {
                case TypeCname:
                {
                    int cnamePos = rdataStart;
                    if (TryReadName(wire, offset, end, ref cnamePos, out string target) && target.Length > 0)
                        aliasOf[target] = attributedTo;
                    break;
                }
                case TypeA when rdLength == 4:
                case TypeAaaa when rdLength == 16:
                {
                    byte[] addressBytes = new byte[rdLength];
                    Buffer.BlockCopy(wire, rdataStart, addressBytes, 0, rdLength);
                    var ttl = TimeSpan.FromSeconds(Math.Min(ttlSeconds, 24 * 60 * 60));
                    records.Add(new DnsAddressRecord(owner, attributedTo, new IPAddress(addressBytes), ttl));
                    break;
                }
            }
        }

        return records.Count == 0 ? empty : records;
    }

    // Reads a (possibly compressed) domain name, advancing `pos` past the name in the record
    // stream. Compression pointers are followed without moving `pos` beyond the pointer itself,
    // which is what the format requires.
    private static bool TryReadName(byte[] wire, int messageStart, int end, ref int pos, out string name)
    {
        var sb = new StringBuilder(64);
        int cursor = pos;
        int afterName = -1;
        int jumps = 0;

        while (true)
        {
            if (cursor < messageStart || cursor >= end) { name = string.Empty; return false; }
            byte len = wire[cursor];

            if (len == 0)
            {
                cursor++;
                if (afterName < 0) afterName = cursor;
                break;
            }

            if ((len & 0xC0) == 0xC0)
            {
                if (cursor + 1 >= end) { name = string.Empty; return false; }
                int pointer = messageStart + (((len & 0x3F) << 8) | wire[cursor + 1]);
                if (afterName < 0) afterName = cursor + 2;
                if (++jumps > MaxNameJumps) { name = string.Empty; return false; }
                cursor = pointer;
                continue;
            }

            if ((len & 0xC0) != 0) { name = string.Empty; return false; } // reserved label type
            cursor++;
            if (cursor + len > end) { name = string.Empty; return false; }
            if (sb.Length > 0) sb.Append('.');
            // DNS labels are ASCII (IDNs travel as punycode), so no encoding negotiation needed.
            sb.Append(Encoding.ASCII.GetString(wire, cursor, len));
            cursor += len;
        }

        pos = afterName;
        name = sb.ToString();
        return true;
    }

    private static ushort ReadUInt16(byte[] b, int at) => (ushort)((b[at] << 8) | b[at + 1]);

    private static uint ReadUInt32(byte[] b, int at)
        => ((uint)b[at] << 24) | ((uint)b[at + 1] << 16) | ((uint)b[at + 2] << 8) | b[at + 3];
}
