namespace TqkLibrary.WinDivert.Redirect.Enums;

// What the redirector does with the target process's IPv6 traffic.
public enum Ipv6Mode
{
    // Capture it exactly like IPv4: a parallel IPv6 NETWORK pump NATs the target's IPv6 flows onto
    // the relay's [::1] listeners, so they get routed, logged and counted like everything else.
    Redirect = 0,

    // Drop it. The target's IPv6 connections fail, so the application falls back to IPv4 (Happy
    // Eyeballs) and is captured there. Use when the way out cannot carry IPv6 at all and you would
    // rather stall those connections than let them escape.
    Block = 1,

    // Leave it alone. The target's IPv6 traffic reaches the network untouched — it does NOT go
    // through the proxy and the real address is exposed. Only for diagnosing.
    Ignore = 2,
}
