using System.Net;

namespace TqkLibrary.WinDivert.Redirect;

// UDP has no connection, so each datagram is its own event. The caller receives the original
// source/destination, the PID, and the payload. They return the bytes (possibly modified) that
// should be forwarded upstream, or null to drop the datagram.
public sealed class RedirectedUdpDatagram
{
    public uint ProcessId { get; }
    public IPEndPoint OriginalSource { get; }
    public IPEndPoint OriginalDestination { get; }
    public byte[] Payload { get; set; }

    public RedirectedUdpDatagram(uint pid, IPEndPoint origSrc, IPEndPoint origDst, byte[] payload)
    {
        ProcessId = pid;
        OriginalSource = origSrc;
        OriginalDestination = origDst;
        Payload = payload;
    }
}
