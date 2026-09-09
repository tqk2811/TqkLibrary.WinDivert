using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace TqkLibrary.WinDivert.Redirect;

// Listens on 127.0.0.1:<ephemeral> and, when IPv6 redirect is enabled, on [::1]:<ephemeral> as
// well. Incoming connections are rewritten packets coming from the target process. The remote
// endpoint of the accepted socket gives us the original source port, which — together with the
// family of the listener that accepted it — is the key into NatTable for recovering the original
// destination.
//
// Two separate listeners rather than one dual-mode socket: a dual-mode socket must bind to [::],
// i.e. every interface, which would expose the relay to the LAN. Loopback-only is worth the second
// socket.
//
// The relay never opens the upstream socket itself — see RedirectedTcpConnection. With no
// handler configured it falls back to RelayDirectAsync (plain pass-through).
public sealed class TcpRelayServer : ITcpRelayServer
{
    private readonly INatTable _nat;
    private readonly TcpConnectionHandler? _handler;
    private readonly ILogger<TcpRelayServer> _logger;
    private readonly TcpListener _listener;
    private readonly TcpListener? _listenerV6;
    private readonly CancellationTokenSource _cts = new();
    private readonly List<Task> _acceptLoops = new();
    // Every connection this relay has accepted and not yet finished. Kept so Dispose can close
    // them itself instead of hoping each handler notices the token: a handler parked in a read
    // hands the socket back only when the read returns, and the whole reason to close here is that
    // the reset has to go out while the NAT stage is still up to carry it back to the process.
    private readonly ConcurrentDictionary<TcpClient, byte> _accepted = new();

    /// <summary>Loopback port the IPv4 relay listens on.</summary>
    public int Port { get; private set; }

    /// <summary>Loopback port the IPv6 relay listens on; 0 when IPv6 redirect is off.</summary>
    public int PortV6 { get; private set; }

    /// <summary>How many accepted connections this relay is still holding open.</summary>
    public int AcceptedCount => _accepted.Count;

    // Raised when a redirected connection is accepted / finished. The connection object carries
    // PID, original destination and live byte counters, so a UI can bind straight to it.
    // Handlers run on the relay's task — keep them short.
    public event Action<RedirectedTcpConnection>? ConnectionOpened;
    public event Action<RedirectedTcpConnection>? ConnectionClosed;

    public TcpRelayServer(
        INatTable nat,
        TcpConnectionHandler? handler,
        ILogger<TcpRelayServer> logger,
        bool enableIpv6 = false)
    {
        _nat = nat ?? throw new ArgumentNullException(nameof(nat));
        _handler = handler;
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _listener = new TcpListener(IPAddress.Loopback, 0);
        if (enableIpv6 && Socket.OSSupportsIPv6)
            _listenerV6 = new TcpListener(IPAddress.IPv6Loopback, 0);
    }

    public void Start()
    {
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _logger.LogDebug("TCP relay listening on 127.0.0.1:{Port}", Port);
        _acceptLoops.Add(Task.Run(() => AcceptLoop(_listener, isIpv6: false, _cts.Token)));

        if (_listenerV6 != null)
        {
            // A machine can have an IPv6 stack that still refuses a ::1 bind (IPv6 disabled per
            // adapter or by policy). Report it as "no IPv6 relay" instead of failing the whole
            // start — the caller then falls back to blocking IPv6, which is the safe answer.
            try
            {
                _listenerV6.Start();
                PortV6 = ((IPEndPoint)_listenerV6.LocalEndpoint).Port;
                _logger.LogDebug("TCP relay listening on [::1]:{Port}", PortV6);
                _acceptLoops.Add(Task.Run(() => AcceptLoop(_listenerV6, isIpv6: true, _cts.Token)));
            }
            catch (SocketException ex)
            {
                PortV6 = 0;
                _logger.LogWarning(ex, "TCP relay could not listen on [::1] ({Error}) — IPv6 will not be redirected", ex.SocketErrorCode);
            }
        }
    }

    private async Task AcceptLoop(TcpListener listener, bool isIpv6, CancellationToken ct)
    {
        string tag = isIpv6 ? "v6" : "v4";
        while (!ct.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
                IPEndPoint? rep = client.Client.RemoteEndPoint as IPEndPoint;
                _logger.LogTrace("accepted[{Family}] from {Remote}", tag, rep);
            }
            catch (ObjectDisposedException) { _logger.LogDebug("accept loop[{Family}] stopped", tag); return; }
            catch (SocketException ex) { _logger.LogDebug("accept loop[{Family}] ended: {Error}", tag, ex.SocketErrorCode); return; }

            _ = Task.Run(() => HandleAsync(client, isIpv6, ct));
        }
    }

    // Everything an accepted connection does, with the socket's fate settled in one place.
    //
    // The setup below can throw before the inner try is reached: reading RemoteEndPoint, and taking
    // the stream inside RedirectedTcpConnection, both fail on a client that has already reset. That
    // is not rare — QUIC falling back to TCP, two racing connections, a cancelled request all do
    // it — and this runs under Task.Run, so the exception went nowhere and the socket stayed open
    // until a finalizer happened to collect it.
    private async Task HandleAsync(TcpClient client, bool isIpv6, CancellationToken ct)
    {
        _accepted[client] = 0;
        try
        {
            await HandleCoreAsync(client, isIpv6, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "an accepted connection ended before it was set up");
        }
        finally
        {
            _accepted.TryRemove(client, out _);
            try { client.Close(); } catch { }
        }
    }

    private async Task HandleCoreAsync(TcpClient client, bool isIpv6, CancellationToken ct)
    {
        IPEndPoint? remote = client.Client.RemoteEndPoint as IPEndPoint;
        if (remote == null)
        {
            _logger.LogDebug("accepted socket has no remote endpoint, closing");
            return;
        }

        // The NAT entry is keyed by the original source port (preserved during rewrite) plus the
        // family of the listener that accepted this connection.
        NatEntry? entry = _nat.Find(protocol: 6, srcPort: (ushort)remote.Port, isIpv6: isIpv6);
        if (entry == null)
        {
            _logger.LogDebug("no NAT entry for srcPort={SrcPort} ipv6={IsIpv6}, closing", remote.Port, isIpv6);
            return;
        }
        using var conn = new RedirectedTcpConnection(
            entry.ProcessId,
            new IPEndPoint(entry.OriginalSourceAddress, entry.OriginalSourcePort),
            entry.OriginalDestination,
            client,
            entry.CreatedUtc);
        // The delay between the SYN and this accept is the one number that tells a stalled pump
        // from a slow network: the handshake runs over loopback, so anything above a few
        // milliseconds is a retransmitted SYN.
        _logger.LogDebug("srcPort={SrcPort} ipv6={IsIpv6} was going to {Destination}:{DestinationPort}, accepted {Ms}ms after its SYN",
            remote.Port, isIpv6, entry.OriginalDestinationAddress, entry.OriginalDestinationPort, (long)conn.CaptureToAccept.TotalMilliseconds);

        try { ConnectionOpened?.Invoke(conn); } catch { }
        try
        {
            if (_handler != null)
                await _handler(conn, ct).ConfigureAwait(false);
            else
                await conn.RelayDirectAsync(ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "connection srcPort={SrcPort} ended with an error", remote.Port);
        }
        finally
        {
            conn.Statistics.MarkEnded();
            try { ConnectionClosed?.Invoke(conn); } catch { }
            _logger.LogDebug("connection srcPort={SrcPort} closed, {Statistics}", remote.Port, conn.Statistics);
        }
    }

    /// <remarks>
    /// The connections already accepted are closed here rather than left to their handlers. The
    /// token alone is not enough: a handler blocked in a read returns only once the socket under
    /// it is closed, and the reset that closing sends has to leave WHILE the NAT stage is still
    /// running — see ProcessRedirector.Dispose. Closing here is also what covers a connection that
    /// has not been routed yet (still being peeked at for its host name) and so is not tracked
    /// anywhere else.
    /// </remarks>
    public void Dispose()
    {
        try { _cts.Cancel(); } catch { }
        try { _listener.Stop(); } catch { }
        try { _listenerV6?.Stop(); } catch { }

        foreach (TcpClient client in _accepted.Keys)
        {
            _accepted.TryRemove(client, out _);
            try { client.Close(); } catch { }
        }

        try { Task.WaitAll(_acceptLoops.ToArray(), TimeSpan.FromSeconds(1)); } catch { }
        _cts.Dispose();
    }
}
