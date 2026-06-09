// Re-export the library's per-kind sub-namespaces plus the Demo's own, so existing code keeps
// referencing these types unqualified after the by-kind namespace split.
global using TqkLibrary.WinDivert.Native.Enums;
global using TqkLibrary.WinDivert.Native.Models;
global using TqkLibrary.WinDivert.Packet.Enums;
global using TqkLibrary.WinDivert.Packet.Models;
global using TqkLibrary.WinDivert.Flow.Models;
global using TqkLibrary.WinDivert.Redirect.Enums;
global using TqkLibrary.WinDivert.Redirect.Models;
global using TqkLibrary.WinDivert.Pipeline.Enums;
global using TqkLibrary.WinDivert.Pipeline.Interfaces;
global using TqkLibrary.WinDivert.Pipeline.Models;
global using TqkLibrary.WinDivert.Demo.CommandModules.Interfaces;
global using TqkLibrary.WinDivert.Demo.Parsing;
global using TqkLibrary.WinDivert.Demo.Running;
global using TqkLibrary.WinDivert.Demo.Logging;
global using TqkLibrary.WinDivert.Demo.Extensions;
global using TqkLibrary.WinDivert.Demo.Process;
global using TqkLibrary.WinDivert.Demo.Process.Models;
