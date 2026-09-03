using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace TqkLibrary.WinDivert.Redirect;

// Listens on 127.0.0.1:<ephemeral>. Incoming connections are rewritten packets coming from
// the target process. The remote endpoint of the accepted socket gives us the original
// source port, which is the key into NatTable for recovering the original destination.
//
// The relay never opens the upstream socket itself — see RedirectedTcpConnection. With no
// handler configured it falls back to RelayDirectAsync (plain pass-through).
public sealed class TcpRelayServer : IDisposable
{
    private readonly NatTable _nat;
    private readonly TcpConnectionHandler? _handler;
    private readonly RedirectLogger _log;
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private Task? _acceptLoop;

    public int Port { get; private set; }

    // Raised when a redirected connection is accepted / finished. The connection object carries
    // PID, original destination and live byte counters, so a UI can bind straight to it.
    // Handlers run on the relay's task — keep them short.
    public event Action<RedirectedTcpConnection>? ConnectionOpened;
    public event Action<RedirectedTcpConnection>? ConnectionClosed;

    public TcpRelayServer(NatTable nat, TcpConnectionHandler? handler, RedirectLogger? logger = null)
    {
        _nat = nat;
        _handler = handler;
        _log = logger ?? RedirectLogger.Null;
        _listener = new TcpListener(IPAddress.Loopback, 0);
    }

    public void Start()
    {
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _log.Log("RLY", $"TcpRelay listening on 127.0.0.1:{Port}");
        _acceptLoop = Task.Run(() => AcceptLoop(_cts.Token));
    }

    private async Task AcceptLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync().ConfigureAwait(false);
                IPEndPoint? rep = client.Client.RemoteEndPoint as IPEndPoint;
                _log.Log("RLY", $"Accepted from {rep}");
            }
            catch (ObjectDisposedException) { _log.Log("RLY", "AcceptLoop disposed"); return; }
            catch (SocketException ex) { _log.Log("RLY", $"AcceptLoop SocketException: {ex.SocketErrorCode}"); return; }

            _ = Task.Run(() => HandleAsync(client, ct));
        }
    }

    private async Task HandleAsync(TcpClient client, CancellationToken ct)
    {
        IPEndPoint? remote = client.Client.RemoteEndPoint as IPEndPoint;
        if (remote == null)
        {
            _log.Log("RLY", "Handle: remote==null, closing");
            client.Close();
            return;
        }

        // The NAT entry is keyed by the original source port (preserved during rewrite).
        NatEntry? entry = _nat.Find(protocol: 6, srcPort: (ushort)remote.Port);
        if (entry == null)
        {
            _log.Log("RLY", $"Handle: NAT miss for srcPort={remote.Port}, closing");
            client.Close();
            return;
        }
        _log.Log("RLY", $"Handle: matched srcPort={remote.Port} -> origDst={entry.OriginalDestinationAddress}:{entry.OriginalDestinationPort}");

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
            _log.Log("RLY", $"Handle: srcPort={remote.Port} ended with {ex.GetType().Name}: {ex.Message}");
        }
        finally
        {
            conn.Statistics.MarkEnded();
            try { ConnectionClosed?.Invoke(conn); } catch { }
            _log.Log("RLY", $"Handle: srcPort={remote.Port} closed {conn.Statistics}");
        }
    }

    public void Dispose()
    {
        try { _cts.Cancel(); } catch { }
        try { _listener.Stop(); } catch { }
        try { _acceptLoop?.Wait(TimeSpan.FromSeconds(1)); } catch { }
        _cts.Dispose();
    }
}
