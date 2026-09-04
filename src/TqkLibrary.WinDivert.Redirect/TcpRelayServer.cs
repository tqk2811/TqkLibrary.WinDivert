using System;
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

    /// <summary>Loopback port the IPv4 relay listens on.</summary>
    public int Port { get; private set; }

    /// <summary>Loopback port the IPv6 relay listens on; 0 when IPv6 redirect is off.</summary>
    public int PortV6 { get; private set; }

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

    private async Task HandleAsync(TcpClient client, bool isIpv6, CancellationToken ct)
    {
        IPEndPoint? remote = client.Client.RemoteEndPoint as IPEndPoint;
        if (remote == null)
        {
            _logger.LogDebug("accepted socket has no remote endpoint, closing");
            client.Close();
            return;
        }

        // The NAT entry is keyed by the original source port (preserved during rewrite) plus the
        // family of the listener that accepted this connection.
        NatEntry? entry = _nat.Find(protocol: 6, srcPort: (ushort)remote.Port, isIpv6: isIpv6);
        if (entry == null)
        {
            _logger.LogDebug("no NAT entry for srcPort={SrcPort} ipv6={IsIpv6}, closing", remote.Port, isIpv6);
            client.Close();
            return;
        }
        _logger.LogDebug("srcPort={SrcPort} ipv6={IsIpv6} was going to {Destination}:{DestinationPort}", remote.Port, isIpv6, entry.OriginalDestinationAddress, entry.OriginalDestinationPort);

        using var conn = new RedirectedTcpConnection(
            entry.ProcessId,
            new IPEndPoint(entry.OriginalSourceAddress, entry.OriginalSourcePort),
            entry.OriginalDestination,
            client);

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

    public void Dispose()
    {
        try { _cts.Cancel(); } catch { }
        try { _listener.Stop(); } catch { }
        try { _listenerV6?.Stop(); } catch { }
        try { Task.WaitAll(_acceptLoops.ToArray(), TimeSpan.FromSeconds(1)); } catch { }
        _cts.Dispose();
    }
}
