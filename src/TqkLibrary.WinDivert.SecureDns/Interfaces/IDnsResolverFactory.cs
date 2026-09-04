using System;

namespace TqkLibrary.WinDivert.SecureDns.Interfaces;

/// <summary>
/// Creates a resolver for one redirect session, which owns it and disposes it. A factory because
/// the endpoint is a per-session setting, and because the resolver holds an HttpClient whose
/// lifetime should follow the session rather than the container.
/// </summary>
public interface IDnsResolverFactory
{
    /// <param name="endpoint">Null uses the default DoH endpoint.</param>
    IDnsResolver Create(Uri? endpoint = null, TimeSpan? timeout = null);
}
