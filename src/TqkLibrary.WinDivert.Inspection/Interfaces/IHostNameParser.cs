namespace TqkLibrary.WinDivert.Inspection.Interfaces;

/// <summary>
/// Reads the host name a client asks for out of the first bytes it sends, without consuming them.
/// One implementation per protocol that carries a name (TLS puts it in the SNI extension, HTTP in
/// the Host header).
/// </summary>
/// <remarks>
/// Implementations must be stateless and safe to call from any thread: one instance serves every
/// connection.
/// </remarks>
public interface IHostNameParser
{
    /// <summary>
    /// How many bytes this parser wants before it gives up. The inspector peeks the largest of
    /// these across the parsers it holds.
    /// </summary>
    int RecommendedPeekSize { get; }

    /// <summary>
    /// Whether these bytes even look like this protocol. False means the inspector can stop
    /// waiting for more of them — this connection will never yield a name to this parser.
    /// </summary>
    bool CanParse(byte[] buffer, int length);

    /// <summary>
    /// True when a name was read. False can mean either "not this protocol" or "the message is
    /// still incomplete" — <see cref="CanParse"/> is what tells the two apart.
    /// </summary>
    bool TryReadHostName(byte[] buffer, int length, out string hostName);
}
