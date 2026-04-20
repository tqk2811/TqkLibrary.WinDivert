using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace TqkLibrary.WinDivert.Redirect;

// Given to the caller when a redirected TCP connection is accepted by the local relay.
// Exposes the raw client stream (bytes coming FROM the target process) and the upstream
// stream (connected to the original destination). Callers may read/modify/write freely
// or call RelayAsync() to pipe both directions verbatim.
public sealed class RedirectedTcpConnection : IDisposable
{
    public uint ProcessId { get; }
    public IPEndPoint OriginalSource { get; }
    public IPEndPoint OriginalDestination { get; }

    public TcpClient ClientTcp { get; }
    public TcpClient UpstreamTcp { get; }

    public Stream ClientStream => ClientTcp.GetStream();
    public Stream UpstreamStream => UpstreamTcp.GetStream();

    public RedirectedTcpConnection(uint pid, IPEndPoint origSrc, IPEndPoint origDst, TcpClient client, TcpClient upstream)
    {
        ProcessId = pid;
        OriginalSource = origSrc;
        OriginalDestination = origDst;
        ClientTcp = client;
        UpstreamTcp = upstream;
    }

    // Default full-duplex pipe. If the caller already handled I/O, do not call this.
    public async Task RelayAsync(CancellationToken ct = default)
    {
        Task c2u = CopyAsync(ClientStream, UpstreamStream, ct);
        Task u2c = CopyAsync(UpstreamStream, ClientStream, ct);
        await Task.WhenAny(c2u, u2c).ConfigureAwait(false);
    }

    private static async Task CopyAsync(Stream from, Stream to, CancellationToken ct)
    {
        byte[] buf = new byte[16 * 1024];
        try
        {
            while (!ct.IsCancellationRequested)
            {
                int n = await from.ReadAsync(buf, 0, buf.Length, ct).ConfigureAwait(false);
                if (n <= 0) return;
                await to.WriteAsync(buf, 0, n, ct).ConfigureAwait(false);
                await to.FlushAsync(ct).ConfigureAwait(false);
            }
        }
        catch
        {
            // swallow; the caller observes completion via the returned task
        }
    }

    public void Dispose()
    {
        try { ClientTcp.Close(); } catch { }
        try { UpstreamTcp.Close(); } catch { }
    }
}
