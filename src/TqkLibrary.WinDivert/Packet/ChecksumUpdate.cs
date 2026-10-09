using System;

namespace TqkLibrary.WinDivert.Packet;

/// <summary>
/// Incremental Internet checksum update (RFC 1624): adjusts a checksum for a few changed words
/// instead of summing the whole packet again.
/// </summary>
/// <remarks>
/// Uses equation 3, <c>HC' = ~(~HC + ~m + m')</c>, rather than RFC 1141's, which can produce
/// 0xFFFF (negative zero) where a full recompute gives 0x0000.
/// </remarks>
public static class ChecksumUpdate
{
    /// <summary>Checksum after one 16-bit word changed from <paramref name="oldWord"/> to <paramref name="newWord"/>.</summary>
    public static ushort Update16(ushort check, ushort oldWord, ushort newWord)
    {
        uint sum = (uint)(ushort)~check + (uint)(ushort)~oldWord + newWord;
        sum = (sum & 0xFFFF) + (sum >> 16);
        sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)~sum;
    }

    /// <summary>
    /// Checksum after a run of bytes changed. Both spans must have the same even length and sit on
    /// a 16-bit boundary of the checksummed data; words are big-endian, as on the wire.
    /// </summary>
    public static ushort UpdateBytes(ushort check, ReadOnlySpan<byte> oldBytes, ReadOnlySpan<byte> newBytes)
    {
        if (oldBytes.Length != newBytes.Length || (oldBytes.Length & 1) != 0)
            throw new ArgumentException("both spans must have the same even length");

        uint sum = (ushort)~check;
        for (int i = 0; i < oldBytes.Length; i += 2)
        {
            sum += (ushort)~((oldBytes[i] << 8) | oldBytes[i + 1]);
            sum += (uint)((newBytes[i] << 8) | newBytes[i + 1]);
        }
        // At most 16 words of 2 x 16 bits each, so the carries fit and two folds are enough.
        sum = (sum & 0xFFFF) + (sum >> 16);
        sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)~sum;
    }
}
