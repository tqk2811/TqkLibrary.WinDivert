namespace TqkLibrary.WinDivert.ProcessControl.Models;

// Lightweight snapshot of a running process: enough to show it in a picker and to match it
// against a user rule (by name or by full path). Taken at enumeration time, never refreshed.
public sealed class ProcessInfo
{
    public uint Id { get; }
    public string Name { get; }

    // Full path of the main module. Null when the process could not be opened (system processes,
    // or a 64/32-bit mismatch) — rules that match on path simply won't match those.
    public string? ExecutablePath { get; }

    public ProcessInfo(uint id, string name, string? path)
    {
        Id = id;
        Name = name;
        ExecutablePath = path;
    }

    public override string ToString() => $"[{Id}] {Name}";
}
