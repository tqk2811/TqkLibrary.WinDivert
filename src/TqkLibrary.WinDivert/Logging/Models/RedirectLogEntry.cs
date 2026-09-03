using System;

namespace TqkLibrary.WinDivert.Logging.Models;

// One diagnostic line. Handed to live subscribers (a UI log pane) as a value, so the consumer
// never has to parse the formatted text back apart.
public sealed class RedirectLogEntry
{
    public DateTime TimestampUtc { get; }

    // Short subsystem tag: TRK (socket tracker), INT (packet interception), RLY (relay),
    // DNS, DOH, RDR (redirector), V6X (IPv6 block), TREE (process tree).
    public string Tag { get; }

    public string Message { get; }

    public RedirectLogEntry(DateTime timestampUtc, string tag, string message)
    {
        TimestampUtc = timestampUtc;
        Tag = tag;
        Message = message;
    }

    public override string ToString() => $"{TimestampUtc:HH:mm:ss.fff} [{Tag}] {Message}";
}
