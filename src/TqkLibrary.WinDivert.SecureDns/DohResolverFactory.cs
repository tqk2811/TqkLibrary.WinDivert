using System;
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
}
