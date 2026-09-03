namespace TqkLibrary.WinDivert.Flow.Models;

// Value stored per tracked UDP bind — carries the owning pid for the same reason TcpFlowState does.
public sealed class UdpBindState
{
    public uint ProcessId { get; }

    public UdpBindState(uint processId)
    {
        ProcessId = processId;
    }
}
