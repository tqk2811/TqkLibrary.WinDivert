using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.WinDivert.Inspection;
using TqkLibrary.WinDivert.Inspection.Interfaces;
using TqkLibrary.WinDivert.Redirect;
using TqkLibrary.WinDivert.Redirect.Models;
using TqkLibrary.WinDivert.SecureDns;
using Xunit;

namespace TqkLibrary.WinDivert.Tests;

/// <summary>
/// Where a redirected connection's name comes from, and what is learned from having read it.
/// </summary>
public class ConnectionHostNameResolverTests
{
    private static readonly IPAddress Destination = IPAddress.Parse("203.0.113.9");

    [Fact]
    public async Task AnameReadFromTheClientIsRememberedAgainstTheAddress()
    {
        var table = new ReverseDnsTable();
        var resolver = new ConnectionHostNameResolver(new StubInspector("example.com"), table);

        using var connection = await ConnectionToAsync(Destination);
        Assert.Equal("example.com", await resolver.TryResolveAsync(connection));

        // The point of remembering it: a UDP flow to the same address carries no name of its own,
        // and this table is the only thing that can give it one. Without it a QUIC flow to a
        // destination a rule names by host matches nothing and leaves direct.
        Assert.Equal("example.com", table.Resolve(Destination));
    }

    [Fact]
    public async Task AConnectionThatRevealsNoNameFallsBackToWhatWasLearnedBefore()
    {
        var table = new ReverseDnsTable();
        table.Add(Destination, "learned.example", TimeSpan.FromMinutes(5));
        var resolver = new ConnectionHostNameResolver(new StubInspector(null), table);

        using var connection = await ConnectionToAsync(Destination);

        Assert.Equal("learned.example", await resolver.TryResolveAsync(connection));
    }

    [Fact]
    public async Task NothingIsLearnedFromAConnectionThatRevealsNoName()
    {
        var table = new ReverseDnsTable();
        var resolver = new ConnectionHostNameResolver(new StubInspector(null), table);

        using var connection = await ConnectionToAsync(Destination);
        Assert.Null(await resolver.TryResolveAsync(connection));

        Assert.Null(table.Resolve(Destination));
    }

    // A redirected connection needs a real accepted socket to wrap; loopback gives us one without
    // the driver being involved.
    private static async Task<RedirectedTcpConnection> ConnectionToAsync(IPAddress destination)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
            TcpClient accepted = await listener.AcceptTcpClientAsync();
            client.Close();
            return new RedirectedTcpConnection(
                pid: 1,
                origSrc: new IPEndPoint(IPAddress.Loopback, 1234),
                origDst: new IPEndPoint(destination, 443),
                accepted);
        }
        finally { listener.Stop(); }
    }

    private sealed class StubInspector : IHostNameInspector
    {
        private readonly string? _name;
        public StubInspector(string? name) => _name = name;

        public Task<string?> TryReadHostNameAsync(
            PeekableStream stream, TimeSpan? peekTimeout = null, CancellationToken cancellationToken = default)
            => Task.FromResult(_name);
    }
}
