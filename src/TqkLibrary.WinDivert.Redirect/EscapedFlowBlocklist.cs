using System.Collections.Concurrent;

namespace TqkLibrary.WinDivert.Redirect;

/// <summary>
/// The pre-existing flows a host has asked to have reset: TCP connections that were open before
/// the tracker could claim them and have been passing through untouched since. Consulted by the
/// NAT stage on every escaped packet; filled by <see cref="Interfaces.IProcessRedirector.ResetEscapedFlows"/>.
/// </summary>
/// <remarks>
/// Shared by the two NAT stages (one per address family) and emptied flow by flow as the tracker
/// reports closes, so a reset connection does not linger here after the process has let it go.
/// Past <see cref="Capacity"/> the set is cleared before the next add: a flow forgotten this way
/// goes back to passing through, which is what it did before the host asked — far better than a
/// set that grows for as long as the redirector runs.
/// </remarks>
public sealed class EscapedFlowBlocklist
{
    private readonly ConcurrentDictionary<FlowKey, byte> _flows = new();

    public EscapedFlowBlocklist(int capacity = 4096)
    {
        if (capacity <= 0) throw new ArgumentOutOfRangeException(nameof(capacity));
        Capacity = capacity;
    }

    public int Capacity { get; }

    public int Count => _flows.Count;

    /// <summary>True when the flow was not listed yet.</summary>
    public bool Add(FlowKey key)
    {
        if (_flows.Count >= Capacity) _flows.Clear();
        return _flows.TryAdd(key, 0);
    }

    public bool Contains(FlowKey key) => _flows.ContainsKey(key);

    public bool Remove(FlowKey key) => _flows.TryRemove(key, out _);
}
