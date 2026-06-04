using System;
using System.Threading.Tasks;

namespace TqkLibrary.WinDivert.Pipeline;

// Adapter so a plain lambda can be registered as middleware without a class.
internal sealed class DelegateMiddleware : IPacketMiddleware
{
    private readonly Func<PacketContext, PacketDelegate, Task> _func;
    public DelegateMiddleware(Func<PacketContext, PacketDelegate, Task> func) => _func = func;
    public Task InvokeAsync(PacketContext context, PacketDelegate next) => _func(context, next);
}
