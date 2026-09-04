using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

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

    public Uri Endpoint { get; }

    public DohResolver(ILogger<DohResolver> logger, Uri? endpoint = null, TimeSpan? timeout = null)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        Endpoint = endpoint ?? DefaultEndpoint;
        _http = new HttpClient { Timeout = timeout ?? TimeSpan.FromSeconds(5) };
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
                _logger.LogWarning("DoH endpoint {Endpoint} answered HTTP {Status}", Endpoint, (int)response.StatusCode);
                return null;
            }
            return await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "DoH resolve via {Endpoint} failed", Endpoint);
            return null;
        }
    }

    public void Dispose()
    {
        try { _http.Dispose(); } catch { }
    }
}
