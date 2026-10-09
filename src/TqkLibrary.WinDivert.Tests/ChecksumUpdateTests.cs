using TqkLibrary.WinDivert.Native.Models;
using TqkLibrary.WinDivert.Packet;
using TqkLibrary.WinDivert.Packet.Models;
using Xunit;

namespace TqkLibrary.WinDivert.Tests;

/// <summary>
/// The incremental checksum patch must land on exactly the bytes a full recompute produces.
/// </summary>
public class ChecksumUpdateTests
{
    private static WinDivertAddress AllValid()
    {
        WinDivertAddress a = default;
        a.IPChecksum = a.TCPChecksum = a.UDPChecksum = true;
        return a;
    }

    // Reference: the ones-complement sum over the pseudo-header and the transport segment.
    private static ushort Fold(uint sum)
    {
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)~sum;
    }

    private static uint SumWords(byte[] b, int offset, int count, uint sum = 0)
    {
        for (int i = 0; i < count; i += 2)
            sum += (uint)((b[offset + i] << 8) | (i + 1 < count ? b[offset + i + 1] : 0));
        return sum;
    }

    private static ushort TransportChecksum(byte[] b, bool v6, bool tcp)
    {
        int t = v6 ? 40 : 20;
        int len = b.Length - t;
        byte[] copy = (byte[])b.Clone();
        copy[t + (tcp ? 16 : 6)] = copy[t + (tcp ? 17 : 7)] = 0;
        uint sum = SumWords(copy, v6 ? 8 : 12, v6 ? 32 : 8);
        sum += (uint)len + (tcp ? 6u : 17u);
        sum = SumWords(copy, t, len, sum);
        return Fold(sum);
    }

    private static ushort Ipv4HeaderChecksum(byte[] b)
    {
        byte[] copy = (byte[])b.Clone();
        copy[10] = copy[11] = 0;
        return Fold(SumWords(copy, 0, 20));
    }

    private static void Put(byte[] b, int at, ushort v)
    {
        b[at] = (byte)(v >> 8);
        b[at + 1] = (byte)v;
    }

    private static ushort Get(byte[] b, int at) => (ushort)((b[at] << 8) | b[at + 1]);

    private static byte[] Build(bool v6, bool tcp, byte[] src, byte[] dst, ushort srcPort, ushort dstPort, byte[] payload, bool fixChecksums = true)
    {
        int ipLen = v6 ? 40 : 20;
        int tLen = (tcp ? 20 : 8) + payload.Length;
        byte[] b = new byte[ipLen + tLen];
        if (v6)
        {
            b[0] = 0x60;
            Put(b, 4, (ushort)tLen);
            b[6] = tcp ? (byte)6 : (byte)17;
            b[7] = 64;
            src.CopyTo(b, 8);
            dst.CopyTo(b, 24);
        }
        else
        {
            b[0] = 0x45;
            Put(b, 2, (ushort)b.Length);
            b[8] = 64;
            b[9] = tcp ? (byte)6 : (byte)17;
            src.CopyTo(b, 12);
            dst.CopyTo(b, 16);
        }
        Put(b, ipLen, srcPort);
        Put(b, ipLen + 2, dstPort);
        if (tcp)
        {
            b[ipLen + 12] = 0x50;  // data offset 5
            b[ipLen + 13] = 0x18;
            Put(b, ipLen + 14, 65535);
        }
        else
        {
            Put(b, ipLen + 4, (ushort)tLen);
        }
        payload.CopyTo(b, ipLen + (tcp ? 20 : 8));
        if (fixChecksums)
        {
            ushort check = TransportChecksum(b, v6, tcp);
            if (!tcp && check == 0) check = 0xFFFF;
            Put(b, ipLen + (tcp ? 16 : 6), check);
            if (!v6) Put(b, 10, Ipv4HeaderChecksum(b));
        }
        return b;
    }

    private static ParsedPacket Parse(byte[] b)
        => PacketParser.Default.TryParse(b, b.Length) ?? throw new InvalidOperationException("test packet did not parse");

    private static byte[] RandomBytes(Random rng, int n)
    {
        byte[] b = new byte[n];
        rng.NextBytes(b);
        return b;
    }

    [Fact]
    public void Update16OfAnUnchangedWordKeepsTheChecksum()
    {
        foreach (ushort check in new ushort[] { 0x0000, 0x0001, 0x1234, 0xFFFE })
            Assert.Equal(check, ChecksumUpdate.Update16(check, 0xABCD, 0xABCD));
    }

    [Fact]
    public void UpdateBytesRejectsOddOrMismatchedSpans()
    {
        Assert.Throws<ArgumentException>(() => ChecksumUpdate.UpdateBytes(0, new byte[3], new byte[3]));
        Assert.Throws<ArgumentException>(() => ChecksumUpdate.UpdateBytes(0, new byte[2], new byte[4]));
    }

    [Fact]
    public void AThousandRandomRewritesEqualAFullRecompute()
    {
        var rng = new Random(20261009);
        WinDivertAddress addr = AllValid();
        for (int i = 0; i < 1000; i++)
        {
            bool v6 = (i & 1) != 0;
            bool tcp = (i & 2) != 0;
            int ipLen = v6 ? 16 : 4;
            byte[] payload = RandomBytes(rng, rng.Next(0, 120));  // odd and even lengths
            byte[] b = Build(v6, tcp, RandomBytes(rng, ipLen), RandomBytes(rng, ipLen),
                (ushort)rng.Next(1, 65536), (ushort)rng.Next(1, 65536), payload);
            ParsedPacket p = Parse(b);
            byte[] newSrc = RandomBytes(rng, ipLen);
            byte[] newDst = RandomBytes(rng, ipLen);
            ushort newSrcPort = (ushort)rng.Next(0, 65536);
            ushort newDstPort = (ushort)rng.Next(0, 65536);

            Assert.True(p.TryRewriteIncremental(newSrc, newSrcPort, newDst, newDstPort, in addr), $"case {i}");

            Assert.True(Build(v6, tcp, newSrc, newDst, newSrcPort, newDstPort, payload).AsSpan().SequenceEqual(b), $"case {i} v6={v6} tcp={tcp}");
        }
    }

    [Fact]
    public void PortOnlyChangeMatchesAFullRecompute()
    {
        byte[] src = { 10, 0, 0, 1 }, dst = { 93, 184, 216, 34 };
        byte[] payload = { 1, 2, 3, 4, 5 };
        byte[] b = Build(false, true, src, dst, 50000, 443, payload);
        WinDivertAddress addr = AllValid();

        Assert.True(Parse(b).TryRewriteIncremental(src, 50001, dst, 8080, in addr));

        Assert.Equal(Build(false, true, src, dst, 50001, 8080, payload), b);
    }

    [Fact]
    public void FullV6AddressChangeMatchesAFullRecompute()
    {
        var rng = new Random(7);
        byte[] payload = RandomBytes(rng, 33);
        byte[] b = Build(true, false, RandomBytes(rng, 16), RandomBytes(rng, 16), 5353, 53, payload);
        byte[] newSrc = RandomBytes(rng, 16);
        byte[] newDst = RandomBytes(rng, 16);
        WinDivertAddress addr = AllValid();

        Assert.True(Parse(b).TryRewriteIncremental(newSrc, 5353, newDst, 9, in addr));

        Assert.Equal(Build(true, false, newSrc, newDst, 5353, 9, payload), b);
    }

    [Fact]
    public void UdpV4WithoutAChecksumStaysWithoutOne()
    {
        byte[] src = { 10, 0, 0, 1 }, dst = { 8, 8, 8, 8 };
        byte[] b = Build(false, false, src, dst, 4000, 53, new byte[] { 9, 9, 9 }, fixChecksums: false);
        Put(b, 10, Ipv4HeaderChecksum(b));  // IP header valid, UDP checksum left at 0
        byte[] loopback = { 127, 0, 0, 1 };
        WinDivertAddress addr = AllValid();

        Assert.True(Parse(b).TryRewriteIncremental(loopback, 4000, loopback, 5000, in addr));

        Assert.Equal(0, Get(b, 26));
        Assert.Equal(loopback, b[12..16]);
        Assert.Equal(loopback, b[16..20]);
        Assert.Equal(5000, Get(b, 22));
        Assert.Equal(Ipv4HeaderChecksum(b), Get(b, 10));
    }

    [Fact]
    public void AUdpResultOfZeroIsWrittenAsFfff()
    {
        // Brute force two payload bytes until the rewritten datagram's checksum is 0x0000.
        byte[] src = { 10, 0, 0, 1 }, dst = { 8, 8, 8, 8 };
        byte[] loopback = { 127, 0, 0, 1 };
        WinDivertAddress addr = AllValid();
        for (int v = 0; v < 65536; v++)
        {
            byte[] payload = { (byte)(v >> 8), (byte)v };
            byte[] after = Build(false, false, loopback, loopback, 4000, 5000, payload, fixChecksums: false);
            if (TransportChecksum(after, false, false) != 0) continue;

            byte[] b = Build(false, false, src, dst, 4000, 53, payload);
            Assert.True(Parse(b).TryRewriteIncremental(loopback, 4000, loopback, 5000, in addr));
            Assert.Equal(0xFFFF, Get(b, 26));
            return;
        }
        Assert.Fail("no payload produced a zero checksum");
    }

    [Theory]
    [InlineData(true, true)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(false, false)]
    public void AClearedChecksumBitRefusesAndLeavesTheBufferAlone(bool tcp, bool clearIpBit)
    {
        byte[] src = { 10, 0, 0, 1 }, dst = { 8, 8, 8, 8 };
        byte[] b = Build(false, tcp, src, dst, 4000, 53, new byte[] { 1, 2, 3 });
        byte[] before = (byte[])b.Clone();
        WinDivertAddress addr = AllValid();
        if (clearIpBit) addr.IPChecksum = false;
        else if (tcp) addr.TCPChecksum = false;
        else addr.UDPChecksum = false;

        Assert.False(Parse(b).TryRewriteIncremental(dst, 1, src, 2, in addr));

        Assert.Equal(before, b);
    }

    [Fact]
    public void AnIpv4FragmentRefusesAndLeavesTheBufferAlone()
    {
        byte[] src = { 10, 0, 0, 1 }, dst = { 8, 8, 8, 8 };
        byte[] b = Build(false, true, src, dst, 4000, 53, new byte[] { 1, 2, 3 });
        b[6] = 0x20;  // More Fragments
        byte[] before = (byte[])b.Clone();
        WinDivertAddress addr = AllValid();

        Assert.False(Parse(b).TryRewriteIncremental(dst, 1, src, 2, in addr));

        Assert.Equal(before, b);
    }

    [Fact]
    public void UdpOverIpv6WithAZeroChecksumRefuses()
    {
        var rng = new Random(3);
        byte[] b = Build(true, false, RandomBytes(rng, 16), RandomBytes(rng, 16), 1, 2, new byte[] { 1 }, fixChecksums: false);
        byte[] before = (byte[])b.Clone();
        byte[] other = RandomBytes(rng, 16);
        WinDivertAddress addr = AllValid();

        Assert.False(Parse(b).TryRewriteIncremental(other, 1, other, 2, in addr));

        Assert.Equal(before, b);
    }

    [Fact]
    public void AMismatchedAddressLengthRefuses()
    {
        byte[] src = { 10, 0, 0, 1 }, dst = { 8, 8, 8, 8 };
        byte[] b = Build(false, true, src, dst, 4000, 53, new byte[] { 1 });
        byte[] before = (byte[])b.Clone();
        WinDivertAddress addr = AllValid();

        Assert.False(Parse(b).TryRewriteIncremental(new byte[16], 1, new byte[16], 2, in addr));

        Assert.Equal(before, b);
    }
}
