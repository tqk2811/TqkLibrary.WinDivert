using System;
using System.CommandLine;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TqkLibrary.WinDivert.Demo.CommandModules;
using TqkLibrary.WinDivert.ProcessControl.DependencyInjection;
using TqkLibrary.WinDivert.Redirect.DependencyInjection;

namespace TqkLibrary.WinDivert.Demo;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        Console.Title = "TqkLibrary.WinDivert Demo";
        Console.WriteLine("== TqkLibrary.WinDivert Demo ==");
        Console.WriteLine("(requires Administrator + WinDivert.dll/WinDivert64.sys next to exe)");

        string logPath = Environment.GetEnvironmentVariable("WINDIVERT_LOG")
            ?? System.IO.Path.Combine(Environment.CurrentDirectory, "windivert-demo.log");
        Console.WriteLine($"Diagnostic log: {logPath}");
        Console.WriteLine();

        await using ServiceProvider services = BuildServices(logPath);

        var root = new RootCommand("TqkLibrary.WinDivert Demo — redirect TCP/UDP traffic of a process via WinDivert.")
        {
            new AttachCommandModule(services).Command,
            new LaunchCommandModule(services).Command,
            new ProxyCommandModule(services).Command,
            new SelfHostCommandModule(services).Command,
        };
        return await root.Parse(args).InvokeAsync().ConfigureAwait(false);
    }

    // The whole wiring of the library, in one place. Everything below AddWinDivertRedirect is
    // registered by the library itself; the host supplies exactly one thing — where log lines go.
    private static ServiceProvider BuildServices(string logPath)
        => new ServiceCollection()
            .AddLogging(builder =>
            {
                builder.SetMinimumLevel(LogLevel.Trace);
                builder.AddProvider(new Logging.DemoLoggerProvider(logPath));
            })
            .AddWinDivertRedirect()
            .AddWinDivertProcessControl()
            .BuildServiceProvider();
}
