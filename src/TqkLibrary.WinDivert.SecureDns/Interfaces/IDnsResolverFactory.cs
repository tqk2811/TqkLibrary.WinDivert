using System;
using System.Net.Http;

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

    /// <summary>
    /// A resolver whose HTTPS goes through <paramref name="handler"/> (e.g. a <c>SocketsHttpHandler</c>
    /// dialing through an outbound). The caller owns the result, and through it the handler when
    /// <paramref name="disposeHandler"/> is true.
    /// </summary>
    IDnsResolver Create(HttpMessageHandler handler, bool disposeHandler, Uri? endpoint = null, TimeSpan? timeout = null);
}
