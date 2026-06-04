using System.Threading;
using TqkLibrary.WinDivert.Flow;
using TqkLibrary.WinDivert.Native;
using TqkLibrary.WinDivert.Packet;
using TqkLibrary.WinDivert.Redirect;

namespace TqkLibrary.WinDivert.Pipeline.Models;

// Per-packet state flowing through the middleware chain. Created once per recv and mutated in
// place by middlewares. One instance is alive at a time per pump (processing is synchronous on
// the pump thread), so middlewares that need to retain anything beyond their synchronous return
// MUST copy it first — the underlying Buffer is the pump's reusable scratch buffer.
public sealed class PacketContext
{
    // The pump's scratch buffer holding the captured packet. Not a copy.
    public byte[] Buffer { get; }

    // Length of the packet within Buffer. Settable so a middleware that rewrites the payload to a
    // different size can report the new length back to the pump.
    public int Length { get; set; }

    // Mutable on purpose (a field, not a property): middlewares write Address.Loopback,
    // Address.Network.IfIdx, etc., and the pump passes `ref ctx.Address` to WinDivertSend.
    // A property returning the struct by value would make those nested writes rvalue errors.
    public WinDivertAddress Address;

    // Parsed view of Buffer, produced once by the pump (null when unparseable). Settable so a
    // middleware that rebuilds the packet can refresh it.
    public ParsedPacket? Packet { get; set; }

    // What the pump should do once the chain returns. Defaults to Pass.
    public PacketDisposition Disposition { get; set; } = PacketDisposition.Pass;

    // Shared per-redirector services available to every middleware.
    public SocketTracker Tracker { get; }
    public NatTable Nat { get; }
    public uint ProcessId { get; }
    public DnsCacheLookup? DnsLookup { get; }
    public IPacketInjector Injector { get; }
    public CancellationToken CancellationToken { get; }

    public PacketContext(
        byte[] buffer,
        SocketTracker tracker,
        NatTable nat,
        uint processId,
        DnsCacheLookup? dnsLookup,
        IPacketInjector injector,
        CancellationToken cancellationToken)
    {
        Buffer = buffer;
        Tracker = tracker;
        Nat = nat;
        ProcessId = processId;
        DnsLookup = dnsLookup;
        Injector = injector;
        CancellationToken = cancellationToken;
    }

    public void Pass() => Disposition = PacketDisposition.Pass;
    public void Drop() => Disposition = PacketDisposition.Drop;
    public void MarkModified() => Disposition = PacketDisposition.Modified;
}
