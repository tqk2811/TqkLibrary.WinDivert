using System;
using System.Net.Http;
using Microsoft.Extensions.Logging;

namespace TqkLibrary.WinDivert.SecureDns;

/// <summary>Creates <see cref="DohResolver"/> instances with the container's logging.</summary>
public sealed class DohResolverFactory : IDnsResolverFactory
{
    private readonly ILoggerFactory _loggerFactory;

    public DohResolverFactory(ILoggerFactory loggerFactory)
    {
        _loggerFactory = loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory));
    }

    public IDnsResolver Create(Uri? endpoint = null, TimeSpan? timeout = null)
        => new DohResolver(_loggerFactory.CreateLogger<DohResolver>(), endpoint, timeout);

    public IDnsResolver Create(HttpMessageHandler handler, bool disposeHandler, Uri? endpoint = null, TimeSpan? timeout = null)
        => new DohResolver(_loggerFactory.CreateLogger<DohResolver>(), handler, disposeHandler, endpoint, timeout);

    /// <summary>As above; <paramref name="logFailuresAsWarning"/> false logs the resolver's failures at Debug (the caller reports them).</summary>
    public IDnsResolver Create(
        HttpMessageHandler handler, bool disposeHandler, Uri? endpoint, TimeSpan? timeout, bool logFailuresAsWarning)
        => new DohResolver(_loggerFactory.CreateLogger<DohResolver>(), handler, disposeHandler, endpoint, timeout, logFailuresAsWarning);
}
