using System.Net;

namespace TqkLibrary.WinDivert.Native.Helpers;

internal static class AddressHelper
{
    public static IPAddress FromWords(uint w0, uint w1, uint w2, uint w3, bool isIpv6)
    {
        if (!isIpv6)
        {
            // WinDivert exposes IPv4 in host byte order; convert to network-order bytes for IPAddress.
            byte[] b = new byte[4];
            b[0] = (byte)(w0 >> 24);
            b[1] = (byte)(w0 >> 16);
            b[2] = (byte)(w0 >> 8);
            b[3] = (byte)w0;
            return new IPAddress(b);
        }
        // WinDivert stores an IPv6 address as four 32-bit words with the LEAST significant word
        // first, so word 0 holds the LAST 32 bits of the address. Writing them in declaration
        // order produces a reversed address: 2402:800:6e08:4ced:5864:c98:a516:8e47 came out as
        // a516:8e47:5864:c98:6e08:4ced:2402:800.
        byte[] ip6 = new byte[16];
        WriteWord(ip6, 0, w3);
        WriteWord(ip6, 4, w2);
        WriteWord(ip6, 8, w1);
        WriteWord(ip6, 12, w0);
        return new IPAddress(ip6);
    }

    private static void WriteWord(byte[] dst, int at, uint w)
    {
        dst[at + 0] = (byte)(w >> 24);
        dst[at + 1] = (byte)(w >> 16);
        dst[at + 2] = (byte)(w >> 8);
        dst[at + 3] = (byte)w;
    }
}
