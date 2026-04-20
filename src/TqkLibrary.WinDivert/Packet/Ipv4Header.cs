using System;
using System.Net;

namespace TqkLibrary.WinDivert.Packet;

// Provides read/write access to an IPv4 header living in a byte buffer.
// All multi-byte fields stay in network byte order on the wire; accessors convert.
public readonly struct Ipv4HeaderView
{
    private readonly byte[] _buffer;
    private readonly int _offset;

    public Ipv4HeaderView(byte[] buffer, int offset)
    {
        _buffer = buffer;
        _offset = offset;
    }

    public int HeaderLength => (_buffer[_offset] & 0x0F) * 4;
    public int TotalLength => (_buffer[_offset + 2] << 8) | _buffer[_offset + 3];
    public byte Protocol => _buffer[_offset + 9];

    public IPAddress Source
    {
        get
        {
            byte[] b = new byte[4];
            Buffer.BlockCopy(_buffer, _offset + 12, b, 0, 4);
            return new IPAddress(b);
        }
        set => WriteIp(value, _offset + 12);
    }

    public IPAddress Destination
    {
        get
        {
            byte[] b = new byte[4];
            Buffer.BlockCopy(_buffer, _offset + 16, b, 0, 4);
            return new IPAddress(b);
        }
        set => WriteIp(value, _offset + 16);
    }

    private void WriteIp(IPAddress addr, int at)
    {
        byte[] bytes = addr.GetAddressBytes();
        if (bytes.Length != 4) throw new ArgumentException("IPv4 address required", nameof(addr));
        Buffer.BlockCopy(bytes, 0, _buffer, at, 4);
    }
}
