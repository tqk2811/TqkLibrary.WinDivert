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

    private static string BuildProtoFilter(bool tcp, bool udp)
    {
        if (tcp && udp) return "tcp or udp";
        if (tcp) return "tcp";
        if (udp) return "udp";
        return "false";
    }
}
