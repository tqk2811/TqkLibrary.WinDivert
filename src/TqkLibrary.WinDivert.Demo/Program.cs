using System;
using System.CommandLine;
using System.Threading.Tasks;
using TqkLibrary.WinDivert.Demo.CommandHelpers;

namespace TqkLibrary.WinDivert.Demo;

internal static class Program
{
    private static Task<int> Main(string[] args)
    {
        Console.Title = "TqkLibrary.WinDivert Demo";
        Console.WriteLine("== TqkLibrary.WinDivert Demo ==");
        Console.WriteLine("(requires Administrator + WinDivert.dll/WinDivert64.sys next to exe)");
        Console.WriteLine();

        var root = new RootCommand("TqkLibrary.WinDivert Demo — redirect TCP/UDP traffic of a process via WinDivert.")
        {
            new AttachCommandHelper().Command,
            new LaunchCommandHelper().Command,
            new ProxyCommandHelper().Command,
            new SelfHostCommandHelper().Command,
        };
        return root.Parse(args).InvokeAsync();
    }
}
