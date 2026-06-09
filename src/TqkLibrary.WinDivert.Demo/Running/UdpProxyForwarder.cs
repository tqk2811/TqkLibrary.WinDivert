using System;
using System.Collections.Concurrent;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.Proxy.Interfaces;
using TqkLibrary.WinDivert.Redirect;

namespace TqkLibrary.WinDivert.Demo.Running;

// Forwards captured UDP datagrams through a SOCKS5 UDP ASSOCIATE tunnel and routes the
// replies back to the originating process via ProcessRedirector.InjectUdpReplyToProcessAsync.
//
// Limitation: SOCKS5 UDP responses identify the peer only by (server endpoint), so if two
// process sockets target the same server we route the reply to whichever client port we
// saw last for that server. For ordinary game/app traffic each (process port -> server)
// flow is unique, so this is rarely an issue in practice.
internal sealed class UdpProxyForwarder : IDisposable
{
    private readonly IProxySource _proxySource;
    private readonly ProcessRedirector _redirector;
    private readonly CancellationToken _externalCt;
    private readonly CancellationTokenSource _cts;
    private readonly ConcurrentDictionary<IPEndPoint, ushort> _serverToClientPort = new();
    private IUdpAssociateSource? _tunnel;
    private Task? _receiveLoop;

    public UdpProxyForwarder(IProxySource proxySource, ProcessRedirector redirector, CancellationToken ct)
    {
        _proxySource = proxySource ?? throw new ArgumentNullException(nameof(proxySource));
        _redirector = redirector ?? throw new ArgumentNullException(nameof(redirector));
        _externalCt = ct;
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
    }

    public IPEndPoint? RelayEndPoint => _tunnel?.RelayEndPoint;

    public async Task InitAsync()
    {
        _tunnel = await _proxySource.GetUdpAssociateSourceAsync(Guid.NewGuid(), _cts.Token).ConfigureAwait(false);
        await _tunnel.AssociateAsync(_cts.Token).ConfigureAwait(false);
        _receiveLoop = Task.Run(() => ReceiveLoopAsync(_cts.Token));
    }

    // Plug this into RedirectOptions.UdpDatagramHandler. Returning null tells the relay NOT to
    // do its default direct upstream send — this forwarder owns the egress and reply legs.
    public byte[]? OnDatagram(RedirectedUdpDatagram dg, CancellationToken ct)
    {
        if (_tunnel is null)
        {
            Console.WriteLine($"  [UDP drop ] pid={dg.ProcessId} {dg.OriginalSource} -> {dg.OriginalDestination}: tunnel not ready");
            return null;
        }

        _serverToClientPort[dg.OriginalDestination] = (ushort)dg.OriginalSource.Port;
        try
        {
            // Fire-and-forget the tunnel send. We can't await inside this sync handler without
            // blocking the relay's receive loop; SendAsync issues the OS call and returns quickly.
            _ = _tunnel.SendAsync(dg.OriginalDestination, dg.Payload, 0, dg.Payload.Length, ct);
            Console.WriteLine($"  [UDP -> px] pid={dg.ProcessId} {dg.OriginalSource} -> {dg.OriginalDestination} ({dg.Payload.Length} bytes)");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  [UDP err  ] {dg.OriginalDestination}: {ex.GetType().Name}: {ex.Message}");
        }
        return null;
    }

    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _tunnel != null)
        {
            UdpAssociateDatagram dg;
            try
            {
                dg = await _tunnel.ReceiveAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { return; }
            catch (ObjectDisposedException) { return; }
            catch (Exception ex)
            {
                Console.WriteLine($"  [UDP recv ] tunnel error: {ex.GetType().Name}: {ex.Message}");
                return;
            }

            if (!_serverToClientPort.TryGetValue(dg.Source, out ushort clientPort))
            {
                Console.WriteLine($"  [UDP drop ] reply from {dg.Source} ({dg.Payload.Length} bytes): no matching client port");
                continue;
            }

            try
            {
                await _redirector.InjectUdpReplyToProcessAsync(clientPort, dg.Payload).ConfigureAwait(false);
                Console.WriteLine($"  [UDP <- px] {dg.Source} -> :{clientPort} ({dg.Payload.Length} bytes)");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  [UDP inj  ] :{clientPort} error: {ex.GetType().Name}: {ex.Message}");
            }
        }
    }

    public void Dispose()
    {
        try { _cts.Cancel(); } catch { }
        try { _tunnel?.Dispose(); } catch { }
        try { _receiveLoop?.Wait(TimeSpan.FromSeconds(1)); } catch { }
        _cts.Dispose();
    }
}
