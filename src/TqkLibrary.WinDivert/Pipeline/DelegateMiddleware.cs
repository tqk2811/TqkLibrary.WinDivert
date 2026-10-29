using System;

namespace TqkLibrary.WinDivert.Pipeline;

// Adapter so a plain lambda can be registered as middleware without a class.
internal sealed class DelegateMiddleware : IPacketMiddleware
{
    private readonly Action<PacketContext, PacketDelegate> _func;
    public DelegateMiddleware(Action<PacketContext, PacketDelegate> func) => _func = func;
    public void Invoke(PacketContext context, PacketDelegate next) => _func(context, next);
}
