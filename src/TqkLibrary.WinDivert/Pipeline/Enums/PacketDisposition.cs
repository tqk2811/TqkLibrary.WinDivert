namespace TqkLibrary.WinDivert.Pipeline.Enums;

// What the pump should do with a packet after the middleware chain has run.
// Mirrors the old PacketInterceptor.ProcessResult, promoted to public so middlewares share it.
public enum PacketDisposition
{
    // Re-inject the packet unchanged (default — nothing claimed it).
    Pass,
    // Packet bytes were edited; the pump recomputes checksums then re-injects.
    Modified,
    // Swallow the packet; the pump sends nothing.
    Drop,
}
