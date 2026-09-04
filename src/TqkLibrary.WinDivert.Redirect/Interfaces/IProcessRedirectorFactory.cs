namespace TqkLibrary.WinDivert.Redirect.Interfaces;

/// <summary>
/// Builds a redirect session. A factory rather than a container registration because a session is
/// configured per run — which process, which protocols, what to do with IPv6 — and owns driver
/// handles and sockets that must be disposed with it, not with the container.
/// </summary>
public interface IProcessRedirectorFactory
{
    /// <summary>
    /// Creates a session, not yet started. The caller owns it and must dispose it; the options are
    /// read at <see cref="IProcessRedirector.Start"/> and not watched afterwards.
    /// </summary>
    IProcessRedirector Create(RedirectOptions options);
}
