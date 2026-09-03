using System;
using System.Text;

namespace TqkLibrary.WinDivert.Inspection;

// Reads the Host header out of a plaintext HTTP/1.x request. Only useful for cleartext HTTP —
// anything over TLS is covered by TlsClientHelloParser instead.
public static class HttpHostParser
{
    // A request line plus the usual header block fits comfortably; Host is normally within the
    // first few hundred bytes.
    public const int RecommendedPeekSize = 1024;

    private static readonly string[] Methods =
    {
        "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "TRACE ", "CONNECT ",
    };

    // Cheap pre-check: does this look like an HTTP request rather than binary traffic?
    public static bool LooksLikeHttp(byte[] buffer, int length)
    {
        if (buffer == null || length < 5) return false;
        string head = Encoding.ASCII.GetString(buffer, 0, Math.Min(length, 8));
        foreach (string m in Methods)
        {
            if (head.StartsWith(m, StringComparison.Ordinal)) return true;
        }
        return false;
    }

    // Returns the Host header value without the port. False when the header is absent or the
    // buffer stops before the header block ends.
    public static bool TryReadHost(byte[] buffer, int length, out string host)
    {
        host = string.Empty;
        if (!LooksLikeHttp(buffer, length)) return false;

        string text = Encoding.ASCII.GetString(buffer, 0, length);
        int lineStart = text.IndexOf("\r\n", StringComparison.Ordinal);
        if (lineStart < 0) return false;
        lineStart += 2;

        while (lineStart < text.Length)
        {
            int lineEnd = text.IndexOf("\r\n", lineStart, StringComparison.Ordinal);
            if (lineEnd < 0) return false;               // header block is truncated
            if (lineEnd == lineStart) return false;      // empty line: headers ended, no Host

            if (string.Compare(text, lineStart, "Host:", 0, 5, StringComparison.OrdinalIgnoreCase) == 0)
            {
                string value = text.Substring(lineStart + 5, lineEnd - lineStart - 5).Trim();
                // Strip the optional ":port"; an IPv6 literal in brackets keeps its colons.
                if (value.StartsWith("[", StringComparison.Ordinal))
                {
                    int close = value.IndexOf(']');
                    if (close > 0) value = value.Substring(1, close - 1);
                }
                else
                {
                    int colon = value.IndexOf(':');
                    if (colon >= 0) value = value.Substring(0, colon);
                }
                host = value;
                return host.Length > 0;
            }

            lineStart = lineEnd + 2;
        }
        return false;
    }
}
