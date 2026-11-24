using TqkLibrary.WinDivert.Packet;
using Xunit;

namespace TqkLibrary.WinDivert.Tests;

/// <summary>
/// The Tcp/Udp views read at the transport offset without checking, so the parser refuses a
/// TCP/UDP packet whose fixed transport header does not fit (backlog B14).
/// </summary>
public class PacketParserBoundsTests
{
    private static byte[] Ipv4(byte protocol, int totalLength)
    {
        var b = new byte[totalLength];
        b[0] = 0x45;
        b[9] = protocol;
        return b;
    }

    private static byte[] Ipv6(byte nextHeader, int totalLength)
    {
        var b = new byte[totalLength];
        b[0] = 0x60;
        b[6] = nextHeader;
        return b;
    }

    [Theory]
    [InlineData(6, 39)]
    [InlineData(17, 27)]
    public void ATruncatedIpv4TransportHeaderIsRefused(byte protocol, int length)
        => Assert.Null(PacketParser.Default.TryParse(Ipv4(protocol, length), length));

    [Theory]
    [InlineData(6, 40)]
    [InlineData(17, 28)]
    public void AnIpv4TransportHeaderThatJustFitsIsParsed(byte protocol, int length)
        => Assert.NotNull(PacketParser.Default.TryParse(Ipv4(protocol, length), length));

    [Theory]
    [InlineData(6, 59)]
    [InlineData(17, 47)]
    public void ATruncatedIpv6TransportHeaderIsRefused(byte protocol, int length)
        => Assert.Null(PacketParser.Default.TryParse(Ipv6(protocol, length), length));

    [Theory]
    [InlineData(6, 60)]
    [InlineData(17, 48)]
    public void AnIpv6TransportHeaderThatJustFitsIsParsed(byte protocol, int length)
        => Assert.NotNull(PacketParser.Default.TryParse(Ipv6(protocol, length), length));

    [Fact]
    public void AProtocolWithoutAHeaderReadIsNotHeldToOne()
        => Assert.NotNull(PacketParser.Default.TryParse(Ipv4(1, 20), 20));
}
