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

    /// <summary>
    /// The same, with a <paramref name="bypass"/> that releases packets the pipeline would not
    /// touch before any of it runs. See <see cref="IPacketBypass"/>.
    /// </summary>
    /// <remarks>
    /// The default ignores the bypass. That is always correct — a bypass only ever saves work the
    /// pipeline would have done to reach the same answer — so a factory written before this
    /// overload keeps working, just without the shortcut.
    /// </remarks>
    IPacketPump Create(string name, IWinDivertHandle handle, PacketDelegate pipeline, IPacketBypass? bypass)
        => Create(name, handle, pipeline);
}
