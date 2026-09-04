namespace TqkLibrary.WinDivert.Pipeline.Interfaces;

/// <summary>
/// Builds a pump around an already-open handle. Exists so a component that owns several pumps can
/// be constructed from the container without also taking a logger factory to hand each one.
/// </summary>
public interface IPacketPumpFactory
{
    /// <summary>
    /// The pump takes ownership of <paramref name="handle"/> and disposes it with itself.
    /// </summary>
    IPacketPump Create(string name, IWinDivertHandle handle, PacketDelegate pipeline);
}
