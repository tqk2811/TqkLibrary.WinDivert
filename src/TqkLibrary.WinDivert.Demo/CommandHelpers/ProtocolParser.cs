using System;
using TqkLibrary.WinDivert.Redirect;

namespace TqkLibrary.WinDivert.Demo.CommandHelpers;

internal static class ProtocolParser
{
    public static RedirectProtocol? Parse(string s)
    {
        s = s.Trim().ToLowerInvariant();
        return s switch
        {
            "t" or "tcp" => RedirectProtocol.Tcp,
            "u" or "udp" => RedirectProtocol.Udp,
            "b" or "both" or "all" => RedirectProtocol.All,
            _ => null,
        };
    }

    public static RedirectProtocol SelectInteractive()
    {
        Console.Write("Protocols [T=TCP, U=UDP, B=both] (default T): ");
        string? s = Console.ReadLine();
        if (string.IsNullOrWhiteSpace(s)) return RedirectProtocol.Tcp;
        return Parse(s) ?? RedirectProtocol.Tcp;
    }
}
