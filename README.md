# TqkLibrary.WinDivert

Redirect one process's TCP/UDP traffic through your own code, using the
[WinDivert](https://reqrypt.org/windivert.html) driver.

The kernel hands you the packets a chosen process sends; the library bends them onto a loopback
relay, so what reaches your code is an ordinary `TcpClient` — with the original destination and the
owning process id attached. Where the connection really goes is then a decision you make in C#,
per connection, not a routing table you have to fight.

Requires Windows 10 or later, Administrator, and `WinDivert.dll` + `WinDivert64.sys` beside the
executable. Targets `net8.0-windows` and `net6.0-windows`.

## The five packages

Each one is separately referenceable, so a host takes only what it uses.

| Package | What it is | Depends on |
| --- | --- | --- |
| `TqkLibrary.WinDivert` | The core: driver handles, packet parsing, the middleware pipeline, and per-process socket tracking. | — |
| `TqkLibrary.WinDivert.SecureDns` | DNS middlewares: learning IP-to-domain from answers on the wire, and answering the target's DNS over HTTPS. | core |
| `TqkLibrary.WinDivert.Inspection` | Reads the host name a client asks for (TLS SNI, HTTP `Host`) without consuming the stream. | — |
| `TqkLibrary.WinDivert.ProcessControl` | Finding processes, launching them suspended, following their children. | — |
| `TqkLibrary.WinDivert.Redirect` | The redirect session itself: NAT onto a loopback relay, and the orchestrator that wires it all up. | all of the above |

`Inspection` and `ProcessControl` never touch the driver, so they work — and can be tested —
without Administrator.

## Getting started

Everything is registered through the container, and the one thing the library asks for in return is
somewhere to put log lines: it logs through `ILogger<T>` and ships no sink of its own.

```csharp
using ServiceProvider services = new ServiceCollection()
    .AddLogging(b => b.AddConsole())
    .AddWinDivertRedirect()        // core + SecureDns + Inspection
    .AddWinDivertProcessControl()
    .BuildServiceProvider();

var options = new RedirectOptions
{
    ProcessId = pid,
    Protocols = RedirectProtocol.All,
    TcpConnectionHandler = async (connection, ct) =>
    {
        // connection.OriginalDestination is where the process THINKS it is going.
        // Nothing is connected until you ask for it, so you can route, rewrite, or refuse.
        await connection.RelayDirectAsync(ct);
    },
};

using IProcessRedirector redirector = services
    .GetRequiredService<IProcessRedirectorFactory>()
    .Create(options);
redirector.Start();
```

A redirect session is deliberately not a registered service: it owns driver handles and sockets, it
is configured per run, and it must be disposed by whoever started it. Ask the factory for one.

## How it works

Two WinDivert layers, doing different jobs:

* **SOCKET layer**, one handle per tracked pid. Its CONNECT event fires *before* the SYN goes out,
  which is what lets a brand-new connection be captured from its very first packet. `SocketTracker`
  also reconciles against the kernel's own TCP/UDP tables, because the event stream alone loses a
  race often enough to matter.
* **NETWORK layer**, one pump per address family. Every captured packet runs through an
  ASP.NET-style middleware pipeline; the NAT stage rewrites the target's outbound packets to
  `127.0.0.1:<relay>` (or `[::1]:<relay>`) and rewrites the relay's replies back to the original
  addresses.

Because the relay is a real socket, the routing decision happens per **connection**, after the
handshake — which is the only point at which the host name is known (SNI). That is why even
"direct" traffic goes through the relay: it costs one copy and buys byte counters, logging, and
rule changes that take effect without re-attaching anything.

### Writing a middleware

```csharp
public sealed class DropPort9000 : IPacketMiddleware
{
    private readonly ISocketTracker _tracker;   // injected: the context carries only the packet
    public DropPort9000(ISocketTracker tracker) => _tracker = tracker;

    public Task InvokeAsync(PacketContext ctx, PacketDelegate next)
    {
        if (ctx.Packet?.DestinationPort == 9000) { ctx.Drop(); return Task.CompletedTask; }
        return next(ctx);   // defer: not ours
    }
}
```

Register it through `RedirectOptions.ConfigureNetworkPipeline`, which is invoked once per address
family — so a callback that news up its middleware gets one instance per pipeline and never has to
be thread-safe across the two pump threads.

### IPv6

`RedirectOptions.Ipv6Mode` decides what happens to the target's IPv6:

* `Redirect` (default) — a parallel IPv6 pipeline running the same NAT stage, pointed at the
  relay's `[::1]` listeners. An IPv6 connection reaches your handler like any other.
* `Block` — drop it, so the application falls back to IPv4 (Happy Eyeballs does this in a couple of
  hundred milliseconds).
* `Ignore` — leave it alone.

The fallbacks are chosen to fail **safe**. No IPv6 stack at all falls back to `Ignore`: the target
cannot produce IPv6 traffic, so there is nothing to leak. A stack but no usable `[::1]` relay falls
back to `Block`, not `Ignore` — a stall the user can see beats traffic quietly leaving unproxied.

Note that the two families have independent source-port spaces on Windows, so every port-keyed
table in the library carries the address family in its key.

### Flows that started without you

A TCP flow can only be captured from its SYN: redirecting the second half of a handshake sends the
two halves of one connection to two different places and kills it. So a flow that began before the
redirector attached is either passed through (default — it keeps working, but that one connection
exposes the real IP) or dropped (`BlockEscapedFlows`), never redirected mid-stream.

Launching the process suspended avoids the question entirely:

```csharp
ISuspendedProcess p = services.GetRequiredService<ISuspendedProcessLauncher>().Launch(exe, args);
redirector.Start();
redirector.AddTrackedProcessId(p.Pid);
p.Resume();          // its first packet is already ours
```

## Demo

`TqkLibrary.WinDivert.Demo` is a console app covering the four ways this gets used: `attach`,
`launch`, `proxy` (send a process through an upstream HTTP/SOCKS proxy), and `selfhost`. Its
`DemoLoggerProvider` is a worked example of the `ILoggerProvider` a host is expected to supply.
