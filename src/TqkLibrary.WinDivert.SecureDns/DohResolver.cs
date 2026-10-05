using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TqkLibrary.WinDivert.SecureDns.Helpers;

namespace TqkLibrary.WinDivert.SecureDns;

/// <summary>
/// Resolves DNS queries over HTTPS (DoH, RFC 8484).
/// </summary>
/// <remarks>
/// DoH uses the SAME DNS wire format as classic UDP/53, so the raw UDP payload is forwarded
/// verbatim and the raw response bytes come back — no DNS (de)serialization needed anywhere on
/// this path.
///
/// The default endpoint is the Cloudflare IP literal https://1.1.1.1/dns-query: an IP avoids a
/// chicken-and-egg bootstrap (resolving the DoH host would itself need DNS), and Cloudflare's
/// certificate carries 1.1.1.1 as an IP SAN so TLS still validates. A hostname endpoint also
/// works, but relies on the OS resolver for that one-time bootstrap lookup.
/// </remarks>
public sealed class DohResolver : IDnsResolver
{
    /// <summary>Used when no endpoint is configured. See the class remarks for why it is an IP.</summary>
    public static Uri DefaultEndpoint { get; } = new Uri("https://1.1.1.1/dns-query");

    private readonly HttpClient _http;
    private readonly ILogger<DohResolver> _logger;

    // A dead endpoint fails every query: one warning per interval says so, with the count held back.
    private readonly LogThrottle _failureThrottle = new LogThrottle(TimeSpan.FromSeconds(30));
    private readonly LogLevel _failureLevel;
    private volatile bool _disposed;
    private volatile string? _lastFailureReason;

    public Uri Endpoint { get; }

    /// <summary>
    /// The most recent failure across concurrent queries (HTTP status or exception message); for
    /// diagnostics only - with several queries in flight it may belong to another query than the one
    /// the caller just saw fail.
    /// </summary>
    public string? LastFailureReason => _lastFailureReason;

    /// <param name="logFailuresAsWarning">False logs failures at Debug: the caller reports them itself.</param>
    public DohResolver(
        ILogger<DohResolver> logger, Uri? endpoint = null, TimeSpan? timeout = null, bool logFailuresAsWarning = true)
        : this(logger, new HttpClientHandler(), disposeHandler: true, endpoint, timeout, logFailuresAsWarning)
    {
    }

    /// <summary>
    /// Sends the HTTPS requests through <paramref name="handler"/> — e.g. a
    /// <c>SocketsHttpHandler</c> whose <c>ConnectCallback</c> dials through a proxy or tunnel.
    /// </summary>
    /// <param name="disposeHandler">True hands the handler over: disposing this resolver disposes it.</param>
    /// <param name="logFailuresAsWarning">False logs failures at Debug: the caller reports them itself.</param>
    public DohResolver(
        ILogger<DohResolver> logger, HttpMessageHandler handler, bool disposeHandler,
        Uri? endpoint = null, TimeSpan? timeout = null, bool logFailuresAsWarning = true)
    {
        _failureLevel = logFailuresAsWarning ? LogLevel.Warning : LogLevel.Debug;
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        if (handler is null) throw new ArgumentNullException(nameof(handler));
        Endpoint = endpoint ?? DefaultEndpoint;
        // HttpClient disposes the handler with itself only when told it owns it.
        _http = new HttpClient(handler, disposeHandler) { Timeout = timeout ?? TimeSpan.FromSeconds(5) };
    }

    public async Task<byte[]?> ResolveAsync(byte[] dnsWireQuery, CancellationToken ct)
    {
        if (dnsWireQuery is null) throw new ArgumentNullException(nameof(dnsWireQuery));
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, Endpoint);
            var content = new ByteArrayContent(dnsWireQuery);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");
            request.Content = content;
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));

            using HttpResponseMessage response = await _http.SendAsync(request, ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                _lastFailureReason = "HTTP " + (int)response.StatusCode;
                if (_failureThrottle.TryEnter(out int heldBack))
                    _logger.Log(_failureLevel, "DoH endpoint {Endpoint} answered HTTP {Status} ({HeldBack} similar failures not logged)",
                        Endpoint, (int)response.StatusCode, heldBack);
                else if (_logger.IsEnabled(LogLevel.Debug))
                    _logger.LogDebug("DoH endpoint {Endpoint} answered HTTP {Status}", Endpoint, (int)response.StatusCode);
                return null;
            }
            byte[] body = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
            _lastFailureReason = null;
            return body;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // The caller gave up: not the endpoint's fault.
            return null;
        }
        catch (Exception ex) when (ex is ObjectDisposedException || (_disposed && ex is OperationCanceledException))
        {
            // Disposed while the query was in flight (HttpClient aborts it with a cancellation): not
            // the endpoint's fault either.
            return null;
        }
        catch (Exception ex)
        {
            _lastFailureReason = ex.GetType().Name + ": " + ex.Message;
            if (_failureThrottle.TryEnter(out int heldBack))
                _logger.Log(_failureLevel, ex, "DoH resolve via {Endpoint} failed ({HeldBack} similar failures not logged)", Endpoint, heldBack);
            else if (_logger.IsEnabled(LogLevel.Debug))
                _logger.LogDebug("DoH resolve via {Endpoint} failed: {Reason}", Endpoint, _lastFailureReason);
            return null;
        }
    }

    public void Dispose()
    {
        _disposed = true;
        try { _http.Dispose(); } catch { }
    }
}
