using System;

namespace TqkLibrary.WinDivert.Pipeline.Interfaces;

/// <summary>
/// A pre-pipeline check a pump runs on every captured packet, straight off the raw buffer: true
/// means no stage of the pipeline would touch this packet, so it is released unchanged at once.
/// </summary>
/// <remarks>
/// Exists because one NETWORK pump carries every packet of the machine, and the full path —
/// parse, build a context, run each stage — is paid by traffic nobody redirects (a game's, say).
/// When the CPU is busy that cost is latency on packets that never needed us.
/// <para>
/// An implementation must be CONSERVATIVE and allocation-light: true only when it knows, for this
/// exact pipeline, that every stage would pass the packet untouched; anything unsure is false and
/// takes the normal path. It runs on the pump thread, before the packet is parsed, so it must
/// bounds-check everything it reads against <c>packet.Length</c>.
/// </para>
/// </remarks>
public interface IPacketBypass
{
    /// <param name="packet">The captured packet, exactly its length.</param>
    /// <param name="address">The address it was captured with.</param>
    bool ShouldRelease(ReadOnlySpan<byte> packet, in WinDivertAddress address);
}
