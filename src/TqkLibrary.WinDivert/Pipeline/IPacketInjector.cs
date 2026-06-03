using TqkLibrary.WinDivert.Native;

namespace TqkLibrary.WinDivert.Pipeline;

// Lets a middleware emit an out-of-band packet on the same WinDivert handle the pump owns —
// used when a middleware produces a reply asynchronously (e.g. DNS-over-HTTPS injects the
// resolved answer after an HTTPS round-trip, long after the original recv returned).
//
// Implemented by PacketPump. WinDivertSend is thread-safe, so calls from background tasks are
// safe; the implementation recomputes checksums before sending. Returns false (rather than
// throwing) once the pump has been disposed, so late injections fail quietly.
public interface IPacketInjector
{
    bool Inject(byte[] buffer, int length, in WinDivertAddress addr);
}
