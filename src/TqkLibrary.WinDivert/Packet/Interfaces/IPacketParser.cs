namespace TqkLibrary.WinDivert.Packet.Interfaces;

/// <summary>
/// Turns the raw bytes of a captured packet into a parsed view of its IP and transport headers.
/// </summary>
public interface IPacketParser
{
    /// <summary>
    /// Returns a view over <paramref name="buffer"/> — not a copy — or null when the bytes are not
    /// an IP packet this parser understands. The view stays valid only as long as the buffer does.
    /// </summary>
    ParsedPacket? TryParse(byte[] buffer, int length);
}
