using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.WinDivert.Native;
using TqkLibrary.WinDivert.Redirect;

namespace TqkLibrary.WinDivert.Flow;

internal readonly struct UdpBindKey : IEquatable<UdpBindKey>
{
    public IPAddress Address { get; }
    public ushort Port { get; }

    public UdpBindKey(IPAddress address, ushort port)
    {
        Address = address;
        Port = port;
    }

    public bool Equals(UdpBindKey other) => Port == other.Port && Equals(Address, other.Address);
    public override bool Equals(object? obj) => obj is UdpBindKey k && Equals(k);
    public override int GetHashCode() => (Address?.GetHashCode() ?? 0) ^ Port;
}

// Uses the SOCKET layer to learn which (localAddr:localPort, remoteAddr:remotePort) tuples
// belong to the target process. CONNECT events fire *before* the SYN is sent, giving the
// interceptor a chance to rewrite outbound packets from the very first one.
public sealed class SocketTracker : IDisposable
{
    private readonly uint _processId;
    private readonly CancellationTokenSource _cts = new();
    private Task? _pumpTask;
    private WinDivertHandle? _handle;

    private readonly ConcurrentDictionary<FlowKey, byte> _tcpFlows = new();
    private readonly ConcurrentDictionary<UdpBindKey, byte> _udpBinds = new();

    public event Action<FlowKey>? TcpConnectEstablished;
    public event Action<FlowKey>? TcpConnectClosed;
    public event Action<IPAddress, ushort>? UdpBindAdded;
    public event Action<IPAddress, ushort>? UdpBindRemoved;

    public SocketTracker(uint processId)
    {
        _processId = processId;
    }

    public bool IsTrackedTcp(FlowKey key) => _tcpFlows.ContainsKey(key);

    public bool IsTrackedUdp(IPAddress localAddr, ushort localPort)
    {
        if (_udpBinds.ContainsKey(new UdpBindKey(localAddr, localPort))) return true;
        // BIND on ANY (0.0.0.0 / ::) accepts any source address at that port.
        if (_udpBinds.ContainsKey(new UdpBindKey(IPAddress.Any, localPort))) return true;
        if (_udpBinds.ContainsKey(new UdpBindKey(IPAddress.IPv6Any, localPort))) return true;
        return false;
    }

    public IReadOnlyCollection<FlowKey> TcpSnapshot => (IReadOnlyCollection<FlowKey>)_tcpFlows.Keys;

    public void Start()
    {
        if (_pumpTask != null) throw new InvalidOperationException("Already started");
        string filter = $"processId == {_processId} and (tcp or udp)";
        DiagnosticLogger.Log("TRK", $"Open filter=\"{filter}\"");
        _handle = WinDivertHandle.Open(
            filter,
            WinDivertLayer.Socket,
            priority: 0,
            flags: WinDivertOpenFlags.Sniff | WinDivertOpenFlags.RecvOnly);
        _pumpTask = Task.Run(() => PumpLoop(_cts.Token));
    }

    private void PumpLoop(CancellationToken ct)
    {
        byte[] dummy = new byte[0];
        while (!ct.IsCancellationRequested)
        {
            if (_handle == null) return;
            if (!_handle.TryRecv(dummy, out _, out WinDivertAddress addr))
                break;
            HandleEvent(addr);
        }
    }

    private void HandleEvent(WinDivertAddress addr)
    {
        if (addr.Layer != WinDivertLayer.Socket) return;
        bool isIpv6 = addr.IPv6;
        var data = addr.Socket;
        IPAddress local = data.GetLocalAddress(isIpv6);
        IPAddress remote = data.GetRemoteAddress(isIpv6);
        ushort lp = data.LocalPort;
        ushort rp = data.RemotePort;
        byte proto = data.Protocol;

        DiagnosticLogger.Log("TRK", $"evt={addr.Event} proto={proto} pid={data.ProcessId} {local}:{lp} -> {remote}:{rp}");

        switch (addr.Event)
        {
            case WinDivertEvent.SocketConnect:
                if (proto == 6)
                {
                    var key = new FlowKey(proto, local, lp, remote, rp);
                    bool added = _tcpFlows.TryAdd(key, 1);
                    DiagnosticLogger.Log("TRK", $"  tcpFlows.add={added} count={_tcpFlows.Count} key={key}");
                    if (added) TcpConnectEstablished?.Invoke(key);
                }
                break;

            case WinDivertEvent.SocketClose:
                if (proto == 6)
                {
                    var key = new FlowKey(proto, local, lp, remote, rp);
                    bool removed = _tcpFlows.TryRemove(key, out _);
                    DiagnosticLogger.Log("TRK", $"  tcpFlows.remove={removed} count={_tcpFlows.Count} key={key}");
                    if (removed) TcpConnectClosed?.Invoke(key);
                }
                else if (proto == 17)
                {
                    if (_udpBinds.TryRemove(new UdpBindKey(local, lp), out _))
                        UdpBindRemoved?.Invoke(local, lp);
                }
                break;

            case WinDivertEvent.SocketBind:
                if (proto == 17)
                {
                    if (_udpBinds.TryAdd(new UdpBindKey(local, lp), 1))
                        UdpBindAdded?.Invoke(local, lp);
                }
                break;
        }
    }

    public void Dispose()
    {
        try { _cts.Cancel(); } catch { }
        try { _handle?.Shutdown(); } catch { }
        try { _pumpTask?.Wait(TimeSpan.FromSeconds(1)); } catch { }
        _handle?.Dispose();
        _cts.Dispose();
    }
}
