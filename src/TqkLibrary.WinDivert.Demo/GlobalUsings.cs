// Re-export the per-kind sub-namespaces of the libraries, plus the Demo's own, so the rest of the
// app references these types unqualified. Global usings do not cross an assembly boundary, so the
// list is stated here rather than inherited.
global using TqkLibrary.WinDivert.Native.Enums;
global using TqkLibrary.WinDivert.Native.Models;
global using TqkLibrary.WinDivert.Packet.Enums;
global using TqkLibrary.WinDivert.Packet.Models;
global using TqkLibrary.WinDivert.Flow.Interfaces;
global using TqkLibrary.WinDivert.Flow.Models;
global using TqkLibrary.WinDivert.Pipeline.Enums;
global using TqkLibrary.WinDivert.Pipeline.Interfaces;
global using TqkLibrary.WinDivert.Pipeline.Models;
global using TqkLibrary.WinDivert.Redirect.Enums;
global using TqkLibrary.WinDivert.Redirect.Interfaces;
global using TqkLibrary.WinDivert.Redirect.Models;
global using TqkLibrary.WinDivert.SecureDns.Interfaces;
global using TqkLibrary.WinDivert.ProcessControl;
global using TqkLibrary.WinDivert.ProcessControl.Interfaces;
global using TqkLibrary.WinDivert.ProcessControl.Models;

global using TqkLibrary.WinDivert.Demo.CommandModules.Interfaces;
global using TqkLibrary.WinDivert.Demo.Parsing;
global using TqkLibrary.WinDivert.Demo.Running;
global using TqkLibrary.WinDivert.Demo.Logging;
global using TqkLibrary.WinDivert.Demo.Extensions;
global using TqkLibrary.WinDivert.Demo.Process;
