using System;
using System.Net;

namespace TqkLibrary.WinDivert.Flow.Interfaces;

/// <summary>
/// Best-effort IP to domain name, read from the machine's DNS client cache. Used to annotate log
/// lines and UI rows; routing decisions use the reverse-DNS table built from answers on the wire,
/// which does not depend on the OS resolver having been the one to ask.
/// </summary>
public interface IDnsCacheLookup : IDisposable
{
    void Start();

    /// <summary>The name(s) last seen for this IP, comma-joined, or null when nothing is known.</summary>
    string? Resolve(IPAddress? ip);
}
