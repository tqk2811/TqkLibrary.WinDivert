using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using TqkLibrary.WinDivert.Flow.Models;
using TqkLibrary.WinDivert.Packet;
using TqkLibrary.WinDivert.Pipeline.Enums;
using TqkLibrary.WinDivert.Pipeline.Interfaces;
using TqkLibrary.WinDivert.Pipeline.Models;
using TqkLibrary.WinDivert.Redirect;
using TqkLibrary.WinDivert.Redirect.Enums;
using TqkLibrary.WinDivert.Redirect.Models;
using Xunit;

namespace TqkLibrary.WinDivert.Tests;

/// <summary>
/// Which NAT rewrites may skip the pump's full checksum recompute. Windows leaves loopback
/// checksums uncomputed while WinDivert marks them valid; patching them incrementally sent the
/// relay's SYN-ACK back with a wrong checksum and every redirected IPv4 connection died.
/// </summary>
public class NatRedirectChecksumTests
{
    private const int RelayPort = 5000;
    private const ushort LocalPort = 50000;
    private const ushort RemotePort = 443;
    private static readonly IPAddress Local = IPAddress.Parse("192.168.1.20");
    private static readonly IPAddress Remote = IPAddress.Parse("93.184.216.34");

    // The relay's SYN-ACK as WinDivert hands it over: captured on loopback, checksum bytes that sum
    // to nothing, both checksum bits set anyway.
    [Fact]
    public async Task TheRelaySynAckFromLoopbackIsLeftForTheFullRecompute()
    {
        var nat = new NatTable();
        nat.Upsert(new NatEntry(42, 6, Local, LocalPort, Remote, RemotePort, ifIdx: 7, subIfIdx: 0));
        PacketContext ctx = Packet(IPAddress.Loopback, RelayPort, IPAddress.Loopback, LocalPort, flags: 0x12);
        ctx.Buffer[10] = 0x00; ctx.Buffer[11] = 0x00;  // IPv4 header checksum never computed
        ctx.Buffer[36] = 0x12; ctx.Buffer[37] = 0x34;  // TCP checksum never computed
        ctx.Address.Loopback = true;
        ctx.Address.Outbound = true;
        ctx.Address.Network.IfIdx = 1;

        await Create(nat, new NatRedirectHeldSynTests.FakeTracker()).InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.Equal(PacketDisposition.Modified, ctx.Disposition);
        Assert.False(ctx.ChecksumsUpdated);
        var p = PacketParser.Default.TryParse(ctx.Buffer, ctx.Length)!;
        Assert.Equal(Remote, p.Source);
        Assert.Equal(RemotePort, p.SourcePort);
        Assert.Equal(Local, p.Destination);
        Assert.Equal(LocalPort, p.DestinationPort);
        Assert.False(ctx.Address.Loopback);
        Assert.False(ctx.Address.Outbound);
        Assert.Equal(7u, ctx.Address.Network.IfIdx);
    }

    // The other direction still takes the fast path: a tracked SYN on a real interface, with
    // checksums the stack really computed, is patched in place and the result is correct.
    [Fact]
    public async Task ATrackedSynOnARealInterfaceIsPatchedInPlaceCorrectly()
    {
        var tracker = new NatRedirectHeldSynTests.FakeTracker();
        tracker.Track(new FlowKey(6, Local, LocalPort, Remote, RemotePort));
        PacketContext ctx = Packet(Local, LocalPort, Remote, RemotePort, flags: 0x02);
        ctx.Address.Outbound = true;
        ctx.Address.Loopback = false;
        ctx.Address.Network.IfIdx = 7;

        await Create(new NatTable(), tracker).InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.Equal(PacketDisposition.Modified, ctx.Disposition);
        Assert.True(ctx.ChecksumsUpdated);
        Assert.Equal(0, Fold(SumWords(ctx.Buffer, 0, 20)) ^ 0xFFFF);
        Assert.Equal(0, Fold(SumWords(ctx.Buffer, 20, 20, PseudoHeader(ctx.Buffer, 20))) ^ 0xFFFF);
    }

    private static NatRedirectMiddleware Create(NatTable nat, NatRedirectHeldSynTests.FakeTracker tracker)
        => new NatRedirectMiddleware(
            nat, tracker, RelayPorts.Ipv4Only(RelayPort, 0), RedirectProtocol.Tcp, rootProcessId: 1,
            NullLogger<NatRedirectMiddleware>.Instance);

    // A 40-byte IPv4 TCP segment with correct checksums and every checksum bit set.
    private static PacketContext Packet(IPAddress src, int srcPort, IPAddress dst, int dstPort, byte flags)
    {
        byte[] b = new byte[40];
        b[0] = 0x45;
        b[3] = 40;
        b[8] = 64;
        b[9] = 6;
        src.GetAddressBytes().CopyTo(b, 12);
        dst.GetAddressBytes().CopyTo(b, 16);
        b[20] = (byte)(srcPort >> 8); b[21] = (byte)srcPort;
        b[22] = (byte)(dstPort >> 8); b[23] = (byte)dstPort;
        b[27] = 1;      // seq
        b[32] = 0x50;   // data offset 5
        b[33] = flags;
        b[34] = 0xFF; b[35] = 0xFF;  // window

        ushort ipCheck = (ushort)~Fold(SumWords(b, 0, 20));
        b[10] = (byte)(ipCheck >> 8); b[11] = (byte)ipCheck;
        ushort tcpCheck = (ushort)~Fold(SumWords(b, 20, 20, PseudoHeader(b, 20)));
        b[36] = (byte)(tcpCheck >> 8); b[37] = (byte)tcpCheck;

        var ctx = new PacketContext(b, new NoInjector(), CancellationToken.None)
        {
            Length = b.Length,
            Packet = PacketParser.Default.TryParse(b, b.Length),
        };
        ctx.Address.IPChecksum = ctx.Address.TCPChecksum = true;
        return ctx;
    }

    private static uint PseudoHeader(byte[] b, int tcpLength)
        => SumWords(b, 12, 8) + 6u + (uint)tcpLength;

    private static uint SumWords(byte[] b, int offset, int count, uint sum = 0)
    {
        for (int i = 0; i < count; i += 2)
            sum += (uint)((b[offset + i] << 8) | b[offset + i + 1]);
        return sum;
    }

    private static ushort Fold(uint sum)
    {
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)sum;
    }

    private sealed class NoInjector : IPacketInjector
    {
        public bool Inject(byte[] buffer, int length, in TqkLibrary.WinDivert.Native.Models.WinDivertAddress addr) => true;
    }
}
