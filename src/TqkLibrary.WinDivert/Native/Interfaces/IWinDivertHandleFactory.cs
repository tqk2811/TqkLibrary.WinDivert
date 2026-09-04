namespace TqkLibrary.WinDivert.Native.Interfaces;

/// <summary>
/// Opens WinDivert handles. Everything that needs the driver takes this rather than calling a
/// static Open, which is what lets a test substitute the driver entirely.
/// </summary>
public interface IWinDivertHandleFactory
{
    /// <summary>
    /// Opens a handle, or throws <see cref="System.ComponentModel.Win32Exception"/> when the
    /// driver refuses — most often because the process is not elevated, or the filter does not
    /// compile.
    /// </summary>
    IWinDivertHandle Open(string filter, WinDivertLayer layer, short priority, WinDivertOpenFlags flags);
}
