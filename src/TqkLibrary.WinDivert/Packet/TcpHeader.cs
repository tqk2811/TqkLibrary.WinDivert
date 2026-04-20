namespace TqkLibrary.WinDivert.Packet;

public readonly struct TcpHeaderView
{
    private readonly byte[] _buffer;
    private readonly int _offset;

    public TcpHeaderView(byte[] buffer, int offset)
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

    public int DataOffset => (_buffer[_offset + 12] >> 4) * 4;

    public bool Syn => (_buffer[_offset + 13] & 0x02) != 0;
    public bool Fin => (_buffer[_offset + 13] & 0x01) != 0;
    public bool Ack => (_buffer[_offset + 13] & 0x10) != 0;
    public bool Rst => (_buffer[_offset + 13] & 0x04) != 0;
}
