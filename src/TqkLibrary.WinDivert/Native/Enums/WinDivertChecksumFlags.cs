using System;

namespace TqkLibrary.WinDivert.Native.Enums;

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
