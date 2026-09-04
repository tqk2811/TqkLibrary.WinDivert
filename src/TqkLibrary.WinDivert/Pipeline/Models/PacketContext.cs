using System.Threading;

namespace TqkLibrary.WinDivert.Pipeline.Models;

/// <summary>
/// Per-packet state flowing through the middleware chain. Created once per recv and mutated in
/// place by middlewares.
/// </summary>
/// <remarks>
/// This carries the PACKET and nothing else. Everything a middleware needs besides the packet —
/// the NAT table, the socket tracker, a DNS cache — is its own dependency and arrives through its
/// constructor, so the pipeline stays a general-purpose packet path with no knowledge of what is
/// built on top of it. (It used to carry those directly, which made the core assembly depend on
/// the redirect feature that defines the NAT table.)
///
/// One instance is alive at a time per pump (processing is synchronous on the pump thread), so a
/// middleware that retains anything beyond its synchronous return MUST copy it first — Buffer is
/// the pump's reusable scratch buffer, and the context object itself is not reused but the bytes
/// behind it are.
/// </remarks>
public sealed class PacketContext
{
    /// <summary>The pump's scratch buffer holding the captured packet. Not a copy.</summary>
    public byte[] Buffer { get; }

    /// <summary>
    /// Length of the packet within Buffer. Settable so a middleware that rewrites the payload to a
    /// different size can report the new length back to the pump.
    /// </summary>
    public int Length { get; set; }

    /// <summary>
    /// Mutable on purpose (a field, not a property): middlewares write Address.Loopback,
    /// Address.Network.IfIdx, etc., and the pump passes <c>ref ctx.Address</c> to WinDivertSend.
    /// A property returning the struct by value would make those nested writes rvalue errors.
    /// </summary>
    public WinDivertAddress Address;

    /// <summary>
    /// Parsed view of Buffer, produced once by the pump (null when unparseable). Settable so a
    /// middleware that rebuilds the packet can refresh it.
    /// </summary>
    public ParsedPacket? Packet { get; set; }

    /// <summary>What the pump should do once the chain returns. Defaults to Pass.</summary>
    public PacketDisposition Disposition { get; set; } = PacketDisposition.Pass;

    /// <summary>
    /// Emits an out-of-band packet on the same handle — for a middleware that produces a reply
    /// asynchronously, long after this context has been recycled.
    /// </summary>
    public IPacketInjector Injector { get; }

    /// <summary>Cancelled when the pump is being torn down.</summary>
    public CancellationToken CancellationToken { get; }

    public PacketContext(
        byte[] buffer,
        IPacketInjector injector,
        CancellationToken cancellationToken)
    {
        Buffer = buffer;
        Injector = injector;
        CancellationToken = cancellationToken;
    }

    public void Pass() => Disposition = PacketDisposition.Pass;
    public void Drop() => Disposition = PacketDisposition.Drop;
    public void MarkModified() => Disposition = PacketDisposition.Modified;
}
