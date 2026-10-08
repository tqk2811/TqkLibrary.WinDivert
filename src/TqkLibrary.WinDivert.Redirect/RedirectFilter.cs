using System.Collections.Generic;

namespace TqkLibrary.WinDivert.Redirect;

/// <summary>
/// Builds the WinDivert filter of a redirect NETWORK handle (the one the NAT stage runs on).
/// </summary>
/// <remarks>
/// Every packet the filter matches makes a round trip through user mode and waits its turn on the
/// single pump thread, so the filter captures only what a stage on that handle can act on:
///   * outbound egress on a real interface — the NAT stage's redirect leg, and everything the
///     DoH / UDP-block stages look at;
///   * loopback packets coming FROM a relay port — the NAT stage's reply leg (both the outbound
///     capture it rewrites and the inbound duplicate it drops);
///   * inbound DNS answers (source port 53), only when answer sniffing is on.
/// The old "every tcp/udp packet" filter also dragged every inbound internet packet of the whole
/// machine through the pump, where NAT just passed it on — pure queueing delay for everyone.
///
/// Caller-supplied middlewares (<see cref="RedirectOptions.ConfigureNetworkPipeline"/>) may need
/// anything, so with those present the broad filter is kept.
/// <para>
/// Without them the legs are split over two handles, each with its own pump thread
/// (<see cref="BuildEgress"/> and <see cref="BuildRelayReply"/>): the reply leg carries everything a
/// redirected process downloads — large loopback segments, each rewritten and re-checksummed — and
/// on one thread every unrelated application's egress packet queued behind those bursts. Measured
/// while browsing: unrelated packets waited ~2ms on average for a pump that was busy ~2% of the time.
/// The egress leg is split again by protocol (<see cref="BuildEgress"/> once with TCP only, once
/// with UDP only): a browser's QUIC bursts made TCP packets of other applications wait 13–17ms on
/// average behind them.
/// </para>
/// </remarks>
public static class RedirectFilter
{
    public static string Build(
        bool ipv6, bool tcp, bool udp,
        int tcpRelayPort, int udpRelayPort,
        bool sniffDnsAnswers, bool captureEverything)
    {
        string family = ipv6 ? "ipv6" : "ip";
        string protos = BuildProtoFilter(tcp, udp);
        // `not impostor` avoids re-capturing packets we reinjected ourselves, which would loop.
        if (captureEverything || !(tcp || udp))
            return $"{family} and ({protos}) and not impostor";

        var legs = new List<string> { "(outbound and not loopback)" };
        if (tcp && tcpRelayPort != 0) legs.Add($"(loopback and tcp.SrcPort == {tcpRelayPort})");
        if (udp && udpRelayPort != 0) legs.Add($"(loopback and udp.SrcPort == {udpRelayPort})");
        if (udp && sniffDnsAnswers) legs.Add("udp.SrcPort == 53");

        return $"{family} and ({protos}) and not impostor and ({string.Join(" or ", legs)})";
    }

    /// <summary>
    /// The egress handle of a split pair: outbound packets on real interfaces, plus inbound DNS
    /// answers when sniffing. Everything the DoH, NAT-redirect and UDP-block stages act on.
    /// </summary>
    public static string BuildEgress(bool ipv6, bool tcp, bool udp, bool sniffDnsAnswers)
    {
        string family = ipv6 ? "ipv6" : "ip";
        string protos = BuildProtoFilter(tcp, udp);
        if (!(tcp || udp)) return $"{family} and ({protos}) and not impostor";

        var legs = new List<string> { "(outbound and not loopback)" };
        if (udp && sniffDnsAnswers) legs.Add("udp.SrcPort == 53");
        return $"{family} and ({protos}) and not impostor and ({string.Join(" or ", legs)})";
    }

    /// <summary>
    /// The reply handle of a split pair: loopback packets from a relay port, both captures of each
    /// (the outbound one NAT rewrites, the inbound duplicate it drops). Null when no relay listens
    /// for this family, so there is no reply leg to capture.
    /// </summary>
    public static string? BuildRelayReply(bool ipv6, bool tcp, bool udp, int tcpRelayPort, int udpRelayPort)
    {
        var legs = new List<string>();
        if (tcp && tcpRelayPort != 0) legs.Add($"(loopback and tcp.SrcPort == {tcpRelayPort})");
        if (udp && udpRelayPort != 0) legs.Add($"(loopback and udp.SrcPort == {udpRelayPort})");
        if (legs.Count == 0) return null;

        string family = ipv6 ? "ipv6" : "ip";
        return $"{family} and not impostor and ({string.Join(" or ", legs)})";
    }

    private static string BuildProtoFilter(bool tcp, bool udp)
    {
        if (tcp && udp) return "tcp or udp";
        if (tcp) return "tcp";
        if (udp) return "udp";
        return "false";
    }
}
