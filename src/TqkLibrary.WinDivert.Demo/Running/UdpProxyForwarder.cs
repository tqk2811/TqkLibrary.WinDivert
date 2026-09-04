using System;
using System.Collections.Concurrent;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.Proxy.Interfaces;
using TqkLibrary.WinDivert.Redirect;
using TqkLibrary.WinDivert.Redirect.Interfaces;

namespace TqkLibrary.WinDivert.Demo.Running;

// Forwards captured UDP datagrams through SOCKS5 UDP ASSOCIATE tunnels and routes the replies
// back to the originating process via ProcessRedirector.InjectUdpReplyToProcessAsync.
//
// One tunnel per PROCESS SOURCE PORT. A SOCKS5 UDP reply identifies only the remote peer, never
// the local socket it belongs to, so a single shared tunnel cannot tell two process sockets
// talking to the same server apart — replies would go to whichever port was seen last. Giving
// each source port its own tunnel makes the tunnel itself the correlation key.
internal sealed class UdpProxyForwarder : IDisposable
{
    private readonly IProxySource _proxySource;
    private readonly IProcessRedirector _redirector;
    private readonly CancellationTokenSource _cts;
    private readonly ConcurrentDictionary<ushort, PortTunnel> _tunnels = new();
    private volatile bool _disposed;

    public UdpProxyForwarder(IProxySource proxySource, IProcessRedirector redirector, CancellationToken ct)
    {
        _proxySource = proxySource ?? throw new ArgumentNullException(nameof(proxySource));
        _redirector = redirector ?? throw new ArgumentNullException(nameof(redirector));
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
    }

    // Endpoint of the tunnel opened first, purely for the startup banner.
    public IPEndPoint? RelayEndPoint { get; private set; }

    // Opens one probe tunnel so a proxy that refuses UDP ASSOCIATE fails fast at startup instead
    // of silently dropping the first datagram. The probe is kept and reused by the first port
    // that needs it, so nothing is wasted.
    public async Task InitAsync()
    {
        IUdpAssociateSource probe = await _proxySource.GetUdpAssociateSourceAsync(Guid.NewGuid(), _cts.Token).ConfigureAwait(false);
        await probe.AssociateAsync(_cts.Token).ConfigureAwait(false);
        RelayEndPoint = probe.RelayEndPoint;
        probe.Dispose();
    }

    // Plug this into RedirectOptions.UdpDatagramHandler. Returning null tells the relay NOT to
    // do its default direct upstream send — this forwarder owns the egress and reply legs.
    public byte[]? OnDatagram(RedirectedUdpDatagram dg, CancellationToken ct)
    {
        if (_disposed) return null;

        ushort clientPort = (ushort)dg.OriginalSource.Port;
        PortTunnel tunnel = _tunnels.GetOrAdd(clientPort, p => new PortTunnel(this, p));
        tunnel.Send(dg.OriginalDestination, dg.Payload);
        return null;
    }

    private void OnReply(ushort clientPort, IPEndPoint from, byte[] payload)
    {
        try
        {
            _redirector.InjectUdpReplyToProcessAsync(clientPort, payload).GetAwaiter().GetResult();
            Console.WriteLine($"  [UDP <- px] {from} -> :{clientPort} ({payload.Length} bytes)");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  [UDP inj  ] :{clientPort} error: {ex.GetType().Name}: {ex.Message}");
        }
    }

    public void Dispose()
    {
        _disposed = true;
        try { _cts.Cancel(); } catch { }
        foreach (var kv in _tunnels) kv.Value.Dispose();
        _tunnels.Clear();
        _cts.Dispose();
    }

    // One SOCKS5 UDP ASSOCIATE tunnel dedicated to a single process source port. The tunnel is
    // associated lazily on the first datagram; datagrams that arrive while the handshake is still
    // running are dropped (UDP is lossy by contract, and the app will retry).
    private sealed class PortTunnel : IDisposable
    {
        private readonly UdpProxyForwarder _owner;
        private readonly ushort _clientPort;
        private readonly CancellationTokenSource _cts;
        private readonly Task _ready;
        private IUdpAssociateSource? _tunnel;
        private Task? _receiveLoop;

        public PortTunnel(UdpProxyForwarder owner, ushort clientPort)
        {
            _owner = owner;
            _clientPort = clientPort;
            _cts = CancellationTokenSource.CreateLinkedTokenSource(owner._cts.Token);
            _ready = Task.Run(() => AssociateAsync(_cts.Token));
        }

        private async Task AssociateAsync(CancellationToken ct)
        {
            try
            {
                IUdpAssociateSource tunnel = await _owner._proxySource
                    .GetUdpAssociateSourceAsync(Guid.NewGuid(), ct).ConfigureAwait(false);
                await tunnel.AssociateAsync(ct).ConfigureAwait(false);
                _tunnel = tunnel;
                _receiveLoop = Task.Run(() => ReceiveLoopAsync(ct));
                Console.WriteLine($"  [UDP assoc] :{_clientPort} -> relay={tunnel.RelayEndPoint}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  [UDP assoc] :{_clientPort} FAILED: {ex.GetType().Name}: {ex.Message}");
            }
        }

        public void Send(IPEndPoint destination, byte[] payload)
        {
            IUdpAssociateSource? tunnel = _tunnel;
            if (tunnel is null)
            {
                Console.WriteLine($"  [UDP drop ] :{_clientPort} -> {destination}: tunnel not ready");
                return;
            }
            try
            {
                // Fire-and-forget: awaiting here would block the relay's receive loop.
                _ = tunnel.SendAsync(destination, payload, 0, payload.Length, _cts.Token);
                Console.WriteLine($"  [UDP -> px] :{_clientPort} -> {destination} ({payload.Length} bytes)");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  [UDP err  ] {destination}: {ex.GetType().Name}: {ex.Message}");
            }
        }

        private async Task ReceiveLoopAsync(CancellationToken ct)
        {
            IUdpAssociateSource? tunnel = _tunnel;
            while (!ct.IsCancellationRequested && tunnel != null)
            {
                UdpAssociateDatagram dg;
                try
                {
                    dg = await tunnel.ReceiveAsync(ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) { return; }
                catch (ObjectDisposedException) { return; }
                catch (Exception ex)
                {
                    Console.WriteLine($"  [UDP recv ] :{_clientPort} tunnel error: {ex.GetType().Name}: {ex.Message}");
                    return;
                }

                // The tunnel belongs to exactly one process port, so no lookup can go wrong here.
                _owner.OnReply(_clientPort, dg.Source, dg.Payload);
            }
        }

        public void Dispose()
        {
            try { _cts.Cancel(); } catch { }
            try { _ready.Wait(TimeSpan.FromSeconds(1)); } catch { }
            try { _tunnel?.Dispose(); } catch { }
            try { _receiveLoop?.Wait(TimeSpan.FromSeconds(1)); } catch { }
            _cts.Dispose();
        }
    }
}
