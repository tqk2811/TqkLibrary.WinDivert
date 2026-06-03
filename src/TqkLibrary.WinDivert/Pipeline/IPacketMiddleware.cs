using System;
using System.Threading.Tasks;

namespace TqkLibrary.WinDivert.Pipeline;

// The next stage in the chain. A middleware calls this to defer to the rest of the pipeline.
public delegate Task PacketDelegate(PacketContext context);

// ASP.NET-style packet middleware. Each middleware either:
//   * sets a disposition (Drop / MarkModified) and returns WITHOUT calling next  → terminal, or
//   * calls `await next(context)`                                                → defer to the
//     rest of the chain (leaving the packet for a later middleware or the Pass terminal).
public interface IPacketMiddleware
{
    Task InvokeAsync(PacketContext context, PacketDelegate next);
}

// Adapter so a plain lambda can be registered as middleware without a class.
internal sealed class DelegateMiddleware : IPacketMiddleware
{
    private readonly Func<PacketContext, PacketDelegate, Task> _func;
    public DelegateMiddleware(Func<PacketContext, PacketDelegate, Task> func) => _func = func;
    public Task InvokeAsync(PacketContext context, PacketDelegate next) => _func(context, next);
}
