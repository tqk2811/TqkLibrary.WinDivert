namespace TqkLibrary.WinDivert.Pipeline.Models;

/// <summary>
/// Why a packet pump's recv loop ended.
/// </summary>
/// <remarks>
/// A pump that stops is not a detail: nothing is being redirected on that handle any more, and
/// every packet it would have captured now goes out as it is. The host has to be able to tell the
/// user, so the reason travels with the notification rather than being left in a log line.
/// </remarks>
public readonly struct PumpStop
{
    public PumpStop(string pumpName, int win32Error)
    {
        PumpName = pumpName;
        Win32Error = win32Error;
    }

    /// <summary>The pump's log name, so a host running several can say which one went.</summary>
    public string PumpName { get; }

    /// <summary>The Win32 error that ended the loop, or 0 when it was shut down deliberately.</summary>
    public int Win32Error { get; }

    /// <summary>True when the pump was asked to stop rather than failing.</summary>
    public bool IsOrderly => Win32Error == 0;
}
