using System;
using System.Net;

namespace TqkLibrary.WinDivert.Packet;

// IPv6 fixed header is 40 bytes; we don't walk extension headers here.
public readonly struct Ipv6HeaderView
{
    private readonly byte[] _buffer;
    private readonly int _offset;

    public Ipv6HeaderView(byte[] buffer, int offset)
    {
        _buffer = buffer;
        _offset = offset;
    }

    public const int HeaderLength = 40;

    public int PayloadLength => (_buffer[_offset + 4] << 8) | _buffer[_offset + 5];
    public byte NextHeader => _buffer[_offset + 6];

    public IPAddress Source
    {
        get
        {
            byte[] b = new byte[16];
            Buffer.BlockCopy(_buffer, _offset + 8, b, 0, 16);
            return new IPAddress(b);
        }
        set => WriteIp(value, _offset + 8);
    }

    public IPAddress Destination
    {
        get
        {
            byte[] b = new byte[16];
            Buffer.BlockCopy(_buffer, _offset + 24, b, 0, 16);
            return new IPAddress(b);
        }
        set => WriteIp(value, _offset + 24);
    }

    private void WriteIp(IPAddress addr, int at)
    {
        byte[] bytes = addr.GetAddressBytes();
        if (bytes.Length != 16) throw new ArgumentException("IPv6 address required", nameof(addr));
        Buffer.BlockCopy(bytes, 0, _buffer, at, 16);
    }
}
