using System;
using Microsoft.Extensions.Logging;

namespace TqkLibrary.WinDivert.Redirect;

/// <summary>
/// Assembles a <see cref="ProcessRedirector"/> from the container's services.
/// </summary>
/// <remarks>
/// The two <c>Func</c> parameters are there because a redirect session needs its OWN reverse-DNS
/// table and its own DNS cache lookup — one session should not read the names another session's
/// processes resolved, and both objects die with the session. Everything else is shared and is
/// injected directly.
/// </remarks>
public sealed class ProcessRedirectorFactory : IProcessRedirectorFactory
{
    private readonly IWinDivertHandleFactory _handleFactory;
    private readonly ISocketTrackerFactory _trackerFactory;
    private readonly IPacketPumpFactory _pumpFactory;
    private readonly IDnsMessageParser _dnsMessageParser;
    private readonly IDnsResolverFactory _dnsResolverFactory;
    private readonly Func<IReverseDnsTable> _reverseDnsFactory;
    private readonly Func<IDnsCacheLookup> _dnsCacheLookupFactory;
    private readonly ILoggerFactory _loggerFactory;

    public ProcessRedirectorFactory(
        IWinDivertHandleFactory handleFactory,
        ISocketTrackerFactory trackerFactory,
        IPacketPumpFactory pumpFactory,
        IDnsMessageParser dnsMessageParser,
        IDnsResolverFactory dnsResolverFactory,
        Func<IReverseDnsTable> reverseDnsFactory,
        Func<IDnsCacheLookup> dnsCacheLookupFactory,
        ILoggerFactory loggerFactory)
    {
        _handleFactory = handleFactory ?? throw new ArgumentNullException(nameof(handleFactory));
        _trackerFactory = trackerFactory ?? throw new ArgumentNullException(nameof(trackerFactory));
        _pumpFactory = pumpFactory ?? throw new ArgumentNullException(nameof(pumpFactory));
        _dnsMessageParser = dnsMessageParser ?? throw new ArgumentNullException(nameof(dnsMessageParser));
        _dnsResolverFactory = dnsResolverFactory ?? throw new ArgumentNullException(nameof(dnsResolverFactory));
        _reverseDnsFactory = reverseDnsFactory ?? throw new ArgumentNullException(nameof(reverseDnsFactory));
        _dnsCacheLookupFactory = dnsCacheLookupFactory ?? throw new ArgumentNullException(nameof(dnsCacheLookupFactory));
        _loggerFactory = loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory));
    }

    public IProcessRedirector Create(RedirectOptions options)
        => new ProcessRedirector(
            options,
            _handleFactory,
            _trackerFactory,
            _pumpFactory,
            _dnsMessageParser,
            _dnsResolverFactory,
            _reverseDnsFactory(),
            _dnsCacheLookupFactory(),
            _loggerFactory);
}
