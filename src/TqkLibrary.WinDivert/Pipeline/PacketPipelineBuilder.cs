using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace TqkLibrary.WinDivert.Pipeline;

// Composes registered middlewares into a single PacketDelegate, ASP.NET-style. Middlewares run
// in registration order (first registered = outermost). Build() wraps them around a terminal
// delegate that runs when no middleware short-circuits — by convention the terminal leaves the
// disposition at its default (Pass), so an unclaimed packet is re-injected unchanged.
public sealed class PacketPipelineBuilder
{
    private readonly List<IPacketMiddleware> _middlewares = new();

    public PacketPipelineBuilder Use(IPacketMiddleware middleware)
    {
        if (middleware is null) throw new ArgumentNullException(nameof(middleware));
        _middlewares.Add(middleware);
        return this;
    }

    public PacketPipelineBuilder Use(Func<PacketContext, PacketDelegate, Task> middleware)
    {
        if (middleware is null) throw new ArgumentNullException(nameof(middleware));
        _middlewares.Add(new DelegateMiddleware(middleware));
        return this;
    }

    public int Count => _middlewares.Count;

    // Default terminal: leave the packet to be passed through unchanged.
    private static readonly PacketDelegate PassTerminal = _ => Task.CompletedTask;

    public PacketDelegate Build() => Build(PassTerminal);

    public PacketDelegate Build(PacketDelegate terminal)
    {
        if (terminal is null) throw new ArgumentNullException(nameof(terminal));
        PacketDelegate app = terminal;
        // Wrap from the inside out so index 0 ends up outermost.
        for (int i = _middlewares.Count - 1; i >= 0; i--)
        {
            IPacketMiddleware middleware = _middlewares[i];
            PacketDelegate next = app;
            app = ctx => middleware.InvokeAsync(ctx, next);
        }
        return app;
    }
}
