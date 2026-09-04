namespace TqkLibrary.WinDivert.Native;

/// <summary>The real driver. Stateless, so one instance serves the whole process.</summary>
public sealed class WinDivertHandleFactory : IWinDivertHandleFactory
{
    public IWinDivertHandle Open(string filter, WinDivertLayer layer, short priority, WinDivertOpenFlags flags)
        => WinDivertHandle.Open(filter, layer, priority, flags);
}
