using System;
using TqkLibrary.WinDivert.Pipeline.Models;

namespace TqkLibrary.WinDivert.Pipeline.Interfaces;

/// <summary>
/// Owns one WinDivert handle and drives every packet it captures through a middleware pipeline.
/// Start it once; Dispose shuts the handle down and waits for the pump thread to leave.
/// </summary>
public interface IPacketPump : IPacketInjector, IDisposable
{
    /// <summary>Short name used in log lines to tell several pumps apart. Not an identity.</summary>
    string Name { get; }

    /// <summary>
    /// Raised once when the recv loop leaves, whether it was shut down or it failed. From that
    /// moment this handle captures nothing, so a host that wants the user to know it stopped
    /// redirecting has to hear about it here.
    /// </summary>
    event Action<PumpStop>? Stopped;

    void Start();
}
