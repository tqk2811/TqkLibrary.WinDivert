namespace TqkLibrary.WinDivert.Packet;

public readonly struct UdpHeaderView
{
    private readonly byte[] _buffer;
    private readonly int _offset;

    public UdpHeaderView(byte[] buffer, int offset)
    {
        _buffer = buffer;
        _offset = offset;
    }

    public ushort SourcePort
    {
        get => (ushort)((_buffer[_offset] << 8) | _buffer[_offset + 1]);
        set { _buffer[_offset] = (byte)(value >> 8); _buffer[_offset + 1] = (byte)value; }
    }

    public ushort DestinationPort
    {
        get => (ushort)((_buffer[_offset + 2] << 8) | _buffer[_offset + 3]);
        set { _buffer[_offset + 2] = (byte)(value >> 8); _buffer[_offset + 3] = (byte)value; }
    }

    public int Length => (_buffer[_offset + 4] << 8) | _buffer[_offset + 5];

    public int PayloadOffset => _offset + 8;
    public int PayloadLength => Length - 8;
}
