using System;
using Microsoft.Extensions.Logging;

namespace TqkLibrary.WinDivert.ProcessControl;

/// <summary>Creates <see cref="ProcessTreeMonitor"/> instances with the container's logging.</summary>
public sealed class ProcessTreeMonitorFactory : IProcessTreeMonitorFactory
{
    private readonly ILoggerFactory _loggerFactory;

    public ProcessTreeMonitorFactory(ILoggerFactory loggerFactory)
    {
        _loggerFactory = loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory));
    }

    public IProcessTreeMonitor Create(uint rootPid, int pollIntervalMs = 500)
        => new ProcessTreeMonitor(rootPid, _loggerFactory.CreateLogger<ProcessTreeMonitor>(), pollIntervalMs);
}
