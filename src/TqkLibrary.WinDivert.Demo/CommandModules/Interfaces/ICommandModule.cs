using System.CommandLine;

namespace TqkLibrary.WinDivert.Demo.CommandModules.Interfaces;

internal interface ICommandModule
{
    Command Command { get; }
}
