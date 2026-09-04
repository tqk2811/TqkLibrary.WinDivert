using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TqkLibrary.WinDivert.Packet;
using TqkLibrary.WinDivert.Pipeline;

namespace TqkLibrary.WinDivert.SecureDns;

/// <summary>
/// Watches classic DNS answers (UDP source port 53) flowing back to the machine and feeds their
/// IP to domain mappings into a <see cref="IReverseDnsTable"/>. Purely observational: every packet
/// is passed on untouched.
/// </summary>
/// <remarks>
/// Answers are read for the whole machine rather than only for tracked processes. A name resolved
/// by the OS resolver service on behalf of the target is the common case on Windows, and a mapping
/// learned from someone else's lookup is still a correct mapping.
/// </remarks>
public sealed class DnsAnswerSniffMiddleware : IPacketMiddleware
{
    private const ushort DnsPort = 53;

    private readonly IReverseDnsTable _table;
    private readonly IDnsMessageParser _parser;
    private readonly ILogger<DnsAnswerSniffMiddleware> _logger;

    public DnsAnswerSniffMiddleware(
        IReverseDnsTable table,
        IDnsMessageParser parser,
        ILogger<DnsAnswerSniffMiddleware> logger)
    {
        _table = table ?? throw new ArgumentNullException(nameof(table));
        _parser = parser ?? throw new ArgumentNullException(nameof(parser));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
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
                    _parser.ParseAddressAnswers(ctx.Buffer, payloadOffset, payloadLen);
                if (records.Count > 0)
                {
                    _table.AddRange(records);
                    _logger.LogTrace("sniffed {Count} DNS answer(s), first={First}", records.Count, records[0]);
                }
            }
        }
        catch (Exception ex)
        {
            // Never let a malformed packet break the pipeline — this stage only observes.
            _logger.LogDebug(ex, "DNS answer sniff failed");
        }

        return next(ctx);
    }
}
