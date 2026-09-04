using System;

namespace TqkLibrary.WinDivert.Redirect.Enums;

[Flags]
public enum RedirectProtocol
{
    None = 0,
    Tcp = 1,
    Udp = 2,
    All = Tcp | Udp,
}
