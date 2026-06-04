namespace TqkLibrary.WinDivert.Demo.Process.Models;

internal sealed class ProcessInfo
{
    public uint Id { get; }
    public string Name { get; }
    public string? ExecutablePath { get; }

    public ProcessInfo(uint id, string name, string? path)
    {
        Id = id;
        Name = name;
        ExecutablePath = path;
    }

    public override string ToString() => $"[{Id}] {Name}";
}
