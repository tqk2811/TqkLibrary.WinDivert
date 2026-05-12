using System;
using System.Net;
using TqkLibrary.Proxy.Authentications;
using TqkLibrary.Proxy.Interfaces;
using TqkLibrary.Proxy.ProxySources;

namespace TqkLibrary.WinDivert.Demo.CommandHelpers;

internal static class ProxyUriParser
{
    public static IProxySource Parse(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            throw new ArgumentException("Proxy URL is empty.", nameof(raw));

        if (!Uri.TryCreate(raw, UriKind.Absolute, out Uri? uri))
            throw new FormatException($"Invalid proxy URL: '{raw}'. Expected http://host:port, socks4://host:port, or socks5://host:port.");

        string scheme = uri.Scheme.ToLowerInvariant();
        (string? user, string? pass) = SplitUserInfo(uri.UserInfo);

        switch (scheme)
        {
            case "http":
            {
                var source = new HttpProxySource(uri);
                if (user != null && pass != null)
                    source.HttpProxyAuthentication = new HttpProxyAuthentication(user, pass);
                return source;
            }
            case "socks4":
            case "socks4a":
            {
                IPEndPoint ep = ResolveEndpoint(uri);
                return new Socks4ProxySource(ep, user) { IsUseSocks4A = scheme == "socks4a" };
            }
            case "socks5":
            case "socks":
            {
                IPEndPoint ep = ResolveEndpoint(uri);
                if (user != null && pass != null)
                    return new Socks5ProxySource(ep, new HttpProxyAuthentication(user, pass));
                return new Socks5ProxySource(ep);
            }
            default:
                throw new NotSupportedException($"Unsupported proxy scheme '{scheme}'. Use http, socks4, socks4a, or socks5.");
        }
    }

    private static (string? user, string? pass) SplitUserInfo(string? userInfo)
    {
        if (string.IsNullOrEmpty(userInfo))
            return (null, null);
        string decoded = Uri.UnescapeDataString(userInfo!);
        int sep = decoded.IndexOf(':');
        if (sep < 0)
            return (decoded, null);
        return (decoded.Substring(0, sep), decoded.Substring(sep + 1));
    }

    private static IPEndPoint ResolveEndpoint(Uri uri)
    {
        if (uri.Port <= 0)
            throw new FormatException($"Proxy URL must include a port: {uri}");

        if (IPAddress.TryParse(uri.Host, out IPAddress? ip))
            return new IPEndPoint(ip, uri.Port);

        IPAddress[] addrs = Dns.GetHostAddresses(uri.Host);
        if (addrs.Length == 0)
            throw new InvalidOperationException($"Cannot resolve host '{uri.Host}'.");
        return new IPEndPoint(addrs[0], uri.Port);
    }
}
