using System.Threading;

namespace TqkLibrary.WinDivert.Redirect;

// Called for each outbound UDP datagram. Return the (possibly rewritten) payload to forward
// to the original destination, or null to drop. Incoming replies are delivered to the process
// unchanged; to modify replies, set ReplyHandler.
public delegate byte[]? UdpDatagramHandler(RedirectedUdpDatagram datagram, CancellationToken ct);
