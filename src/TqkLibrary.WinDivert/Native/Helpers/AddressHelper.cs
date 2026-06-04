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
        byte[] ip6 = new byte[16];
        WriteWord(ip6, 0, w0);
        WriteWord(ip6, 4, w1);
        WriteWord(ip6, 8, w2);
        WriteWord(ip6, 12, w3);
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
