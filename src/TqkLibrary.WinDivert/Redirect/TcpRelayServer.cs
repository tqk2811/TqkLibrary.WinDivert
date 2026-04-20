using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace TqkLibrary.WinDivert.Redirect;

// Listens on 127.0.0.1:<ephemeral>. Incoming connections are rewritten packets coming from
// the target process. The remote endpoint of the accepted socket gives us the original
// source port, which is the key into NatTable for recovering the original destination.
public sealed class TcpRelayServer : IDisposable
{
    private readonly NatTable _nat;
    private readonly TcpConnectionHandler? _handler;
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private Task? _acceptLoop;

    public int Port { get; private set; }

    public TcpRelayServer(NatTable nat, TcpConnectionHandler? handler)
    {
        _nat = nat;
        _handler = handler;
        _listener = new TcpListener(IPAddress.Loopback, 0);
    }

    public void Start()
    {
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
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
            }
            catch (ObjectDisposedException) { return; }
            catch (SocketException) { return; }

            _ = Task.Run(() => HandleAsync(client, ct));
        }
    }

    private async Task HandleAsync(TcpClient client, CancellationToken ct)
    {
        IPEndPoint? remote = client.Client.RemoteEndPoint as IPEndPoint;
        if (remote == null)
        {
            client.Close();
            return;
        }

        // The NAT entry is keyed by the original source port (preserved during rewrite).
        NatEntry? entry = _nat.Find(protocol: 6, srcPort: (ushort)remote.Port);
        if (entry == null)
        {
            client.Close();
            return;
        }

        TcpClient upstream = new TcpClient();
        try
        {
            await upstream.ConnectAsync(entry.OriginalDestinationAddress, entry.OriginalDestinationPort).ConfigureAwait(false);
        }
        catch
        {
            client.Close();
            upstream.Close();
            return;
        }

        using var conn = new RedirectedTcpConnection(
            entry.ProcessId,
            new IPEndPoint(entry.OriginalSourceAddress, entry.OriginalSourcePort),
            entry.OriginalDestination,
            client,
            upstream);

        try
        {
            if (_handler != null)
                await _handler(conn, ct).ConfigureAwait(false);
            else
                await conn.RelayAsync(ct).ConfigureAwait(false);
        }
        catch
        {
            // connection teardown observed via the using block
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
