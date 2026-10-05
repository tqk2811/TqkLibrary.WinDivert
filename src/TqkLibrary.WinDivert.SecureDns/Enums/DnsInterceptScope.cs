namespace TqkLibrary.WinDivert.SecureDns.Enums;

/// <summary>Whose classic DNS/53 queries <see cref="DnsOverHttpsMiddleware"/> takes over.</summary>
public enum DnsInterceptScope
{
    // Only queries sent from a socket the tracker attributes to a target process. Note that most
    // Windows applications resolve through the Dnscache service (svchost), so their lookups never
    // leave from their own sockets and are not caught here.
    TrackedProcesses = 0,

    // Every outbound UDP/53 on a real interface, whichever process sent it — the Dnscache service
    // included. This is what actually moves a whole machine's DNS onto DoH.
    WholeMachine = 1,
}
