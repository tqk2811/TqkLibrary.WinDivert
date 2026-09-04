using System;

namespace TqkLibrary.WinDivert.Pipeline.Interfaces;

/// <summary>
/// Owns one WinDivert handle and drives every packet it captures through a middleware pipeline.
/// Start it once; Dispose shuts the handle down and waits for the pump thread to leave.
/// </summary>
public interface IPacketPump : IPacketInjector, IDisposable
{
    /// <summary>Short name used in log lines to tell several pumps apart. Not an identity.</summary>
    string Name { get; }

    void Start();
}
