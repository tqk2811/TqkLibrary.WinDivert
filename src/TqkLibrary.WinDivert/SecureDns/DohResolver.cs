using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.WinDivert.Redirect;

namespace TqkLibrary.WinDivert.SecureDns;

// Resolves DNS queries over HTTPS (DoH, RFC 8484). DoH uses the SAME DNS wire format as classic
// UDP/53, so we forward the raw UDP payload verbatim and return the raw response bytes — no DNS
// (de)serialization needed.
//
// Default endpoint is the Cloudflare IP literal https://1.1.1.1/dns-query: using an IP avoids a
// chicken-and-egg bootstrap (resolving the DoH host would itself need DNS), and Cloudflare's
// certificate carries 1.1.1.1 as an IP SAN so TLS still validates. A hostname endpoint also works
// but relies on the OS resolver for the one-time bootstrap lookup.
public sealed class DohResolver : IDisposable
{
    private readonly HttpClient _http;

    public Uri Endpoint { get; }

    public DohResolver(Uri? endpoint = null, TimeSpan? timeout = null)
    {
        Endpoint = endpoint ?? new Uri("https://1.1.1.1/dns-query");
#if NET462
        // net462 does not negotiate TLS 1.2 by default; without this the DoH handshake fails.
        try { System.Net.ServicePointManager.SecurityProtocol |= System.Net.SecurityProtocolType.Tls12; } catch { }
#endif
        _http = new HttpClient { Timeout = timeout ?? TimeSpan.FromSeconds(5) };
    }

    // Returns the raw DNS response wire bytes, or null on any failure (timeout, TLS, non-2xx,
    // network). Fail-closed: the caller has already dropped the original query, so a null result
    // simply lets the client time out and retry — no traffic leaks.
    public async Task<byte[]?> ResolveAsync(byte[] dnsWireQuery, CancellationToken ct)
    {
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
                DiagnosticLogger.Log("DOH", $"HTTP {(int)response.StatusCode} from {Endpoint}");
                return null;
            }
            return await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            DiagnosticLogger.Log("DOH", $"resolve failed via {Endpoint}: {ex.GetType().Name}: {ex.Message}");
            return null;
        }
    }

    public void Dispose()
    {
        try { _http.Dispose(); } catch { }
    }
}
