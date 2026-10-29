namespace TqkLibrary.WinDivert.Pipeline.Interfaces;

// ASP.NET-style packet middleware. Each middleware either:
//   * sets a disposition (Drop / MarkModified) and returns WITHOUT calling next  → terminal, or
//   * calls `next(context)`                                                      → defer to the
//     rest of the chain (leaving the packet for a later middleware or the Pass terminal).
// Synchronous on purpose: it runs on the pump thread that every packet of the machine waits on;
// slow work goes to a background task and re-injects its result through IPacketInjector.
public interface IPacketMiddleware
{
    void Invoke(PacketContext context, PacketDelegate next);
}
