using System.Net;

namespace TqkLibrary.WinDivert.Redirect;

/// <summary>
/// Asked once per UDP flow, on the packet path, BEFORE the datagram is NAT-redirected: should this
/// flow go through the relay at all? Return false to leave it completely alone.
/// </summary>
/// <remarks>
/// This exists because "direct" is not something the relay can deliver for UDP. A redirected
/// datagram leaves from the relay's own socket, on a port the NAT table does not know, so its
/// reply comes back to the tool instead of to the process — the egress leg works and the reply leg
/// does not. TCP has no such problem: the relay owns both ends of a stream socket.
///
/// So a flow the host would route direct must never be redirected in the first place. Returning
/// false makes the packet pass through untouched, exactly as if the process were not tracked: it
/// reaches the real destination from the process's own socket and the reply comes straight back.
/// The trade-off is explicit — that flow carries the machine's real address, so answer false only
/// where the host has decided a direct route is what it wants.
///
/// Called on the pump thread, once per datagram that has no NAT entry yet, so it must be quick and
/// must not throw. Null means "redirect everything", the behaviour from before this hook existed.
/// </remarks>
/// <param name="processId">The tracked process the datagram belongs to.</param>
/// <param name="destinationAddress">Where the process is really sending it.</param>
/// <param name="destinationPort">The real destination port.</param>
/// <param name="isIpv6">Which address family — the two have independent port spaces.</param>
public delegate bool UdpRedirectPredicate(
    uint processId, IPAddress destinationAddress, ushort destinationPort, bool isIpv6);
