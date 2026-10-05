namespace TqkLibrary.WinDivert.SecureDns;

/// <summary>
/// Builds a SERVFAIL reply from the bytes of the query it answers, so a client whose DoH lookup
/// failed gets an immediate negative answer instead of waiting out its own timeout.
/// </summary>
internal static class DnsServFail
{
    private const int HeaderLength = 12;

    /// <summary>
    /// The query's ID, opcode and RD bit are kept, QR/RA/RCODE=2 set, CD kept, and every section after the
    /// question dropped. When the question section cannot be walked the reply is the bare header
    /// with QDCOUNT=0. Returns null when the query is too short to carry a DNS header.
    /// </summary>
    public static byte[]? Build(byte[] query)
    {
        if (query == null || query.Length < HeaderLength) return null;

        int end = FindQuestionEnd(query);
        byte[] reply = new byte[end];
        Buffer.BlockCopy(query, 0, reply, 0, end);

        reply[2] |= 0x80;                                     // QR = response
        // RA=1, Z/AD cleared, CD kept from the query, RCODE = SERVFAIL.
        reply[3] = (byte)(0x80 | (reply[3] & 0x10) | 0x02);
        for (int i = 6; i < HeaderLength; i++) reply[i] = 0;  // ANCOUNT/NSCOUNT/ARCOUNT
        if (end == HeaderLength) { reply[4] = 0; reply[5] = 0; }  // no question kept
        return reply;
    }

    // Offset just after the question section (names in a question are never compressed in practice),
    // or the header length when the section is not exactly what QDCOUNT says.
    private static int FindQuestionEnd(byte[] q)
    {
        int count = (q[4] << 8) | q[5];
        int pos = HeaderLength;
        for (int n = 0; n < count; n++)
        {
            while (true)
            {
                if (pos >= q.Length) return HeaderLength;
                byte len = q[pos];
                if (len == 0) { pos++; break; }
                if ((len & 0xC0) != 0) return HeaderLength;   // pointer / reserved label type
                pos += 1 + len;
            }
            pos += 4;                                          // QTYPE + QCLASS
            if (pos > q.Length) return HeaderLength;
        }
        return pos;
    }
}
