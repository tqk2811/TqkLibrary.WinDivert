using System;

namespace TqkLibrary.WinDivert.Native;

public enum WinDivertLayer : uint
{
    Network = 0,
    NetworkForward = 1,
    Flow = 2,
    Socket = 3,
    Reflect = 4,
}

public enum WinDivertEvent : uint
{
    NetworkPacket = 0,
    FlowEstablished = 1,
    FlowDeleted = 2,
    SocketBind = 3,
    SocketConnect = 4,
    SocketListen = 5,
    SocketAccept = 6,
    SocketClose = 7,
    ReflectOpen = 8,
    ReflectClose = 9,
}

[Flags]
public enum WinDivertOpenFlags : ulong
{
    None = 0,
    Sniff = 0x0001,
    Drop = 0x0002,
    RecvOnly = 0x0004,
    ReadOnly = RecvOnly,
    SendOnly = 0x0008,
    WriteOnly = SendOnly,
    NoInstall = 0x0010,
    Fragments = 0x0020,
}

public enum WinDivertParam : uint
{
    QueueLength = 0,
    QueueTime = 1,
    QueueSize = 2,
    VersionMajor = 3,
    VersionMinor = 4,
}

public enum WinDivertShutdown : uint
{
    Recv = 0x1,
    Send = 0x2,
    Both = 0x3,
}

[Flags]
public enum WinDivertChecksumFlags : ulong
{
    All = 0,
    NoIPChecksum = 1,
    NoICMPChecksum = 2,
    NoICMPv6Checksum = 4,
    NoTCPChecksum = 8,
    NoUDPChecksum = 16,
}
