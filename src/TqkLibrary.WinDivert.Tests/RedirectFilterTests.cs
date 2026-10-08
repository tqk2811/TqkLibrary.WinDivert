using TqkLibrary.WinDivert.Redirect;
using Xunit;

namespace TqkLibrary.WinDivert.Tests;

/// <summary>
/// The redirect NETWORK handle must capture only what its stages act on — inbound internet
/// traffic used to queue on the pump for nothing.
/// </summary>
public class RedirectFilterTests
{
    [Theory]
    [InlineData(false, "ip")]
    [InlineData(true, "ipv6")]
    public void TcpOnlyCapturesEgressAndTheRelaysLoopbackReplies(bool ipv6, string family)
    {
        string filter = RedirectFilter.Build(ipv6, tcp: true, udp: false, tcpRelayPort: 5000, udpRelayPort: 0,
            sniffDnsAnswers: false, captureEverything: false);

        Assert.Equal(
            $"{family} and (tcp) and not impostor and ((outbound and not loopback) or (loopback and tcp.SrcPort == 5000))",
            filter);
    }

    [Theory]
    [InlineData(false, "ip")]
    [InlineData(true, "ipv6")]
    public void UdpOnlyCapturesEgressAndTheUdpRelaysLoopbackReplies(bool ipv6, string family)
    {
        string filter = RedirectFilter.Build(ipv6, tcp: false, udp: true, tcpRelayPort: 0, udpRelayPort: 6000,
            sniffDnsAnswers: false, captureEverything: false);

        Assert.Equal(
            $"{family} and (udp) and not impostor and ((outbound and not loopback) or (loopback and udp.SrcPort == 6000))",
            filter);
    }

    [Theory]
    [InlineData(false, "ip")]
    [InlineData(true, "ipv6")]
    public void TcpAndUdpCaptureBothRelays(bool ipv6, string family)
    {
        string filter = RedirectFilter.Build(ipv6, tcp: true, udp: true, tcpRelayPort: 5000, udpRelayPort: 6000,
            sniffDnsAnswers: false, captureEverything: false);

        Assert.Equal(
            $"{family} and (tcp or udp) and not impostor and ((outbound and not loopback) or (loopback and tcp.SrcPort == 5000) or (loopback and udp.SrcPort == 6000))",
            filter);
    }

    // UDP captured only for a DoH / block stage: no UDP relay, so no loopback UDP leg.
    [Fact]
    public void UdpWithoutAUdpRelayCapturesOnlyItsEgress()
    {
        string filter = RedirectFilter.Build(false, tcp: true, udp: true, tcpRelayPort: 5000, udpRelayPort: 0,
            sniffDnsAnswers: false, captureEverything: false);

        Assert.Equal(
            "ip and (tcp or udp) and not impostor and ((outbound and not loopback) or (loopback and tcp.SrcPort == 5000))",
            filter);
    }

    // The answer sniffer reads inbound DNS answers, the one inbound non-loopback thing a stage
    // on this handle needs.
    [Fact]
    public void DnsSniffingAddsDnsAnswers()
    {
        string filter = RedirectFilter.Build(false, tcp: true, udp: true, tcpRelayPort: 5000, udpRelayPort: 6000,
            sniffDnsAnswers: true, captureEverything: false);

        Assert.EndsWith(" or udp.SrcPort == 53)", filter);
        Assert.DoesNotContain("inbound", filter);
    }

    // Caller middlewares may need anything, so they keep the old broad capture.
    [Theory]
    [InlineData(false, "ip")]
    [InlineData(true, "ipv6")]
    public void CallerMiddlewaresKeepTheBroadFilter(bool ipv6, string family)
    {
        string filter = RedirectFilter.Build(ipv6, tcp: true, udp: true, tcpRelayPort: 5000, udpRelayPort: 6000,
            sniffDnsAnswers: false, captureEverything: true);

        Assert.Equal($"{family} and (tcp or udp) and not impostor", filter);
    }

    // Split pair: the egress handle never sees the relay's loopback replies, so unrelated
    // applications' packets do not queue behind a redirected download.
    [Theory]
    [InlineData(false, "ip")]
    [InlineData(true, "ipv6")]
    public void TheEgressHandleCapturesNoLoopback(bool ipv6, string family)
    {
        string filter = RedirectFilter.BuildEgress(ipv6, tcp: true, udp: true, sniffDnsAnswers: false);

        Assert.Equal($"{family} and (tcp or udp) and not impostor and ((outbound and not loopback))", filter);
    }

    [Fact]
    public void TheEgressHandleKeepsDnsAnswersWhenSniffing()
    {
        string filter = RedirectFilter.BuildEgress(ipv6: false, tcp: true, udp: true, sniffDnsAnswers: true);

        Assert.Equal("ip and (tcp or udp) and not impostor and ((outbound and not loopback) or udp.SrcPort == 53)", filter);
    }

    [Theory]
    [InlineData(false, "ip")]
    [InlineData(true, "ipv6")]
    public void TheReplyHandleCapturesOnlyLoopbackFromRelayPorts(bool ipv6, string family)
    {
        string? filter = RedirectFilter.BuildRelayReply(ipv6, tcp: true, udp: true, tcpRelayPort: 5000, udpRelayPort: 6000);

        Assert.Equal(
            $"{family} and not impostor and ((loopback and tcp.SrcPort == 5000) or (loopback and udp.SrcPort == 6000))",
            filter);
    }

    [Fact]
    public void NoRelayPortMeansNoReplyHandle()
    {
        Assert.Null(RedirectFilter.BuildRelayReply(ipv6: false, tcp: true, udp: true, tcpRelayPort: 0, udpRelayPort: 0));
        Assert.Null(RedirectFilter.BuildRelayReply(ipv6: false, tcp: false, udp: true, tcpRelayPort: 5000, udpRelayPort: 0));
    }
}
