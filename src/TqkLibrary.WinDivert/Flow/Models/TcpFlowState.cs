namespace TqkLibrary.WinDivert.Flow.Models;

// Value stored per tracked TCP flow. ProcessId is what makes per-process routing possible when
// one SocketTracker follows several pids at once (root + children): the NAT stage stamps the
// real owner onto each NatEntry instead of the redirector's root pid.
//
// ExpireTick: 0 = live; positive = Environment.TickCount at which the flow may be reaped.
public sealed class TcpFlowState
{
    public uint ProcessId { get; }
    public long ExpireTick { get; set; }

    public TcpFlowState(uint processId, long expireTick = 0)
    {
        ProcessId = processId;
        ExpireTick = expireTick;
    }
}
