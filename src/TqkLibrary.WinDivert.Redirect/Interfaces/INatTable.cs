namespace TqkLibrary.WinDivert.Redirect.Interfaces;

/// <summary>
/// Remembers, for each redirected flow, where it was really going — so the relay can find out what
/// the process asked for, and the reply leg can put the original addresses back.
/// </summary>
/// <remarks>
/// Keyed by (protocol, address family, original source port) with NO pid in the key, deliberately.
/// Windows hands out a source port that is unique machine-wide per protocol AND per family, so two
/// processes can never hold the same key at once — which is what makes this safe even when the
/// redirector follows many pids. The relay knows only the source port of the loopback connection
/// it accepted plus which of its two listeners accepted it, and that pair identifies exactly one
/// flow. The owning pid rides along in the value.
/// </remarks>
public interface INatTable
{
    int Count { get; }

    /// <summary>
    /// Records a flow, replacing whatever held that key. Overwriting is correct: the OS only
    /// recycles a source port once the previous flow is gone.
    /// </summary>
    void Upsert(NatEntry entry);

    /// <summary>The flow that used this source port, or null when there is none.</summary>
    NatEntry? Find(byte protocol, ushort srcPort, bool isIpv6);

    bool Remove(byte protocol, ushort srcPort, bool isIpv6);
}
