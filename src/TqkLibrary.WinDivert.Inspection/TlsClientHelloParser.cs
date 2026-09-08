using System;
using System.Text;
using TqkLibrary.WinDivert.Inspection.Interfaces;

namespace TqkLibrary.WinDivert.Inspection;

// Extracts the SNI host name from a TLS ClientHello. This is the most reliable name a redirected
// connection carries: it is what the client intends to talk to, before any DNS guesswork.
//
// Deliberately tolerant — an unrecognised, fragmented or non-TLS first flight simply yields false,
// and the caller falls back to reverse DNS or to the raw IP.
public sealed class TlsClientHelloParser : IHostNameParser
{
    private const byte HandshakeContentType = 0x16;
    private const byte ClientHelloType = 0x01;
    private const ushort ExtensionServerName = 0x0000;
    private const byte NameTypeHostName = 0x00;

    // A ClientHello used to fit in 2048 with room to spare, and that was the size here. Post-quantum
    // key agreement changed it: Chrome and Edge offering X25519MLKEM768 send 2.0-2.3KB, with the
    // ~1.2KB key_share ahead of server_name — so the SNI lands past 2048 and the parse simply
    // failed. Nothing reported it; routing by domain quietly fell back to reverse DNS or to the raw
    // address, which is a different route than the user asked for.
    //
    // 8192 covers that with margin for the extension sets that come next, and costs nothing when
    // the hello is smaller: this is a ceiling on one peek, not an amount waited for.
    public int RecommendedPeekSize => 8192;

    // A handshake record declares its own length in its first five bytes. Until that many have
    // arrived the SNI may still be on its way; once they have, this hello is all there is.
    public bool WantsMoreData(byte[] buffer, int length)
    {
        if (!CanParse(buffer, length)) return length < 3;
        if (length < 5) return true;

        int recordLength = (buffer[3] << 8) | buffer[4];
        return length < recordLength + 5;
    }

    // True when the buffer starts like a TLS handshake record — cheap pre-check before peeking
    // further or attempting a full parse.
    public bool CanParse(byte[] buffer, int length)
        => buffer != null && length >= 3 && buffer[0] == HandshakeContentType && buffer[1] == 0x03;

    public bool TryReadHostName(byte[] buffer, int length, out string serverName)
    {
        serverName = string.Empty;
        if (!CanParse(buffer, length)) return false;

        try
        {
            int pos = 0;
            // ---- TLSPlaintext record ----
            pos += 3;                                        // type + legacy version
            int recordLength = ReadUInt16(buffer, ref pos, length);
            if (recordLength <= 0) return false;
            int recordEnd = Math.Min(length, pos + recordLength);

            // ---- Handshake ----
            if (pos >= recordEnd || buffer[pos] != ClientHelloType) return false;
            pos++;
            int handshakeLength = ReadUInt24(buffer, ref pos, recordEnd);
            int handshakeEnd = Math.Min(recordEnd, pos + handshakeLength);

            pos += 2;                                        // client_version
            pos += 32;                                       // random
            if (pos >= handshakeEnd) return false;

            int sessionIdLength = buffer[pos++];
            pos += sessionIdLength;

            int cipherSuitesLength = ReadUInt16(buffer, ref pos, handshakeEnd);
            pos += cipherSuitesLength;

            if (pos >= handshakeEnd) return false;
            int compressionLength = buffer[pos++];
            pos += compressionLength;

            if (pos + 2 > handshakeEnd) return false;        // no extensions at all
            int extensionsLength = ReadUInt16(buffer, ref pos, handshakeEnd);
            int extensionsEnd = Math.Min(handshakeEnd, pos + extensionsLength);

            // ---- extensions ----
            while (pos + 4 <= extensionsEnd)
            {
                int extType = ReadUInt16(buffer, ref pos, extensionsEnd);
                int extLength = ReadUInt16(buffer, ref pos, extensionsEnd);
                int extEnd = pos + extLength;
                if (extEnd > extensionsEnd) return false;

                if (extType == ExtensionServerName)
                {
                    int listPos = pos;
                    int listLength = ReadUInt16(buffer, ref listPos, extEnd);
                    int listEnd = Math.Min(extEnd, listPos + listLength);
                    while (listPos + 3 <= listEnd)
                    {
                        byte nameType = buffer[listPos++];
                        int nameLength = ReadUInt16(buffer, ref listPos, listEnd);
                        if (listPos + nameLength > listEnd) return false;
                        if (nameType == NameTypeHostName && nameLength > 0)
                        {
                            serverName = Encoding.ASCII.GetString(buffer, listPos, nameLength);
                            return serverName.Length > 0;
                        }
                        listPos += nameLength;
                    }
                    return false;
                }

                pos = extEnd;
            }
        }
        catch
        {
            // Any indexing surprise means "not parseable" — the caller has a fallback.
        }
        return false;
    }

    private static int ReadUInt16(byte[] b, ref int pos, int limit)
    {
        if (pos + 2 > limit) throw new IndexOutOfRangeException();
        int v = (b[pos] << 8) | b[pos + 1];
        pos += 2;
        return v;
    }

    private static int ReadUInt24(byte[] b, ref int pos, int limit)
    {
        if (pos + 3 > limit) throw new IndexOutOfRangeException();
        int v = (b[pos] << 16) | (b[pos + 1] << 8) | b[pos + 2];
        pos += 3;
        return v;
    }
}
