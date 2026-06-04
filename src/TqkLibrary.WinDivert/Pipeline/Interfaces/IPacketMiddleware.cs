using System.Threading.Tasks;

namespace TqkLibrary.WinDivert.Pipeline.Interfaces;

// ASP.NET-style packet middleware. Each middleware either:
//   * sets a disposition (Drop / MarkModified) and returns WITHOUT calling next  → terminal, or
//   * calls `await next(context)`                                                → defer to the
//     rest of the chain (leaving the packet for a later middleware or the Pass terminal).
public interface IPacketMiddleware
{
    Task InvokeAsync(PacketContext context, PacketDelegate next);
}
