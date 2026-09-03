using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using TqkLibrary.WinDivert.Packet;
using TqkLibrary.WinDivert.Pipeline;
using TqkLibrary.WinDivert.Redirect;

namespace TqkLibrary.WinDivert.SecureDns;

// Watches classic DNS answers (UDP source port 53) flowing back to the machine and feeds the
// IP -> domain mappings into a ReverseDnsTable. Purely observational: every packet is passed on
// untouched via next().
//
// Answers are read for the whole machine rather than only for tracked processes: a name resolved
// by the OS resolver service (svchost) on behalf of the target is the common case on Windows, and
// a mapping learned from someone else's lookup is still a correct mapping.
public sealed class DnsAnswerSniffMiddleware : IPacketMiddleware
{
    private const ushort DnsPort = 53;

    private readonly ReverseDnsTable _table;

    public DnsAnswerSniffMiddleware(ReverseDnsTable table)
    {
        _table = table ?? throw new ArgumentNullException(nameof(table));
    }

    public Task InvokeAsync(PacketContext ctx, PacketDelegate next)
    {
        ParsedPacket? p = ctx.Packet;
        if (p == null || !p.IsUdp || p.SourcePort != DnsPort)
            return next(ctx);

        try
        {
            int payloadOffset = p.Udp.PayloadOffset;
            int available = ctx.Length - payloadOffset;
            int udpPayloadLen = p.Udp.PayloadLength;
            int payloadLen = (udpPayloadLen >= 0 && udpPayloadLen < available) ? udpPayloadLen : available;
            if (payloadLen > 0)
            {
                IReadOnlyList<DnsAddressRecord> records =
                    DnsMessageParser.ParseAddressAnswers(ctx.Buffer, payloadOffset, payloadLen);
                if (records.Count > 0)
                {
                    _table.AddRange(records);
                    ctx.Logger.Log("DNS", $"sniff {records.Count} answer(s), first={records[0]}");
                }
            }
        }
        catch (Exception ex)
        {
            // Never let a malformed packet break the pipeline — this stage only observes.
            ctx.Logger.Log("DNS", $"sniff failed: {ex.GetType().Name}: {ex.Message}");
        }

        return next(ctx);
    }
}
