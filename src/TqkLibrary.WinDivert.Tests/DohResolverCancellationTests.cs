using Microsoft.Extensions.Logging;
using TqkLibrary.WinDivert.SecureDns;
using Xunit;

namespace TqkLibrary.WinDivert.Tests;

/// <summary>A caller giving up, or the resolver being disposed mid-query, is not a DoH failure.</summary>
public class DohResolverCancellationTests
{
    private static readonly byte[] Query = { 0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 };

    private sealed class CapturingLogger : ILogger<DohResolver>
    {
        public List<LogLevel> Levels { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (Levels) Levels.Add(logLevel);
        }
    }

    // Holds every request until it is cancelled, signalling when one has arrived.
    private sealed class BlockingHandler : HttpMessageHandler
    {
        public TaskCompletionSource Arrived { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Arrived.TrySetResult();
            await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
            throw new InvalidOperationException("unreachable");
        }
    }

    private sealed class ThrowingHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => throw new HttpRequestException("boom");
    }

    [Fact]
    public async Task Cancelling_through_the_token_returns_null_without_a_warning()
    {
        var logger = new CapturingLogger();
        var handler = new BlockingHandler();
        using var resolver = new DohResolver(logger, handler, disposeHandler: true);
        using var cts = new CancellationTokenSource();

        Task<byte[]?> pending = resolver.ResolveAsync(Query, cts.Token);
        await handler.Arrived.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cts.Cancel();

        Assert.Null(await pending.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Empty(logger.Levels);
        Assert.Null(resolver.LastFailureReason);
    }

    [Fact]
    public async Task Disposing_the_resolver_mid_query_returns_null_without_a_warning()
    {
        var logger = new CapturingLogger();
        var handler = new BlockingHandler();
        var resolver = new DohResolver(logger, handler, disposeHandler: true);

        Task<byte[]?> pending = resolver.ResolveAsync(Query, CancellationToken.None);
        await handler.Arrived.Task.WaitAsync(TimeSpan.FromSeconds(5));
        resolver.Dispose();

        Assert.Null(await pending.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Empty(logger.Levels);
        Assert.Null(resolver.LastFailureReason);
    }

    [Fact]
    public async Task A_real_failure_still_warns_and_records_the_reason()
    {
        var logger = new CapturingLogger();
        using var resolver = new DohResolver(logger, new ThrowingHandler(), disposeHandler: true);

        Assert.Null(await resolver.ResolveAsync(Query, CancellationToken.None));

        Assert.Equal(new[] { LogLevel.Warning }, logger.Levels);
        Assert.Contains("boom", resolver.LastFailureReason);
    }

    [Fact]
    public async Task A_real_failure_logs_at_debug_when_the_caller_reports_it()
    {
        var logger = new CapturingLogger();
        using var resolver = new DohResolver(
            logger, new ThrowingHandler(), disposeHandler: true, logFailuresAsWarning: false);

        Assert.Null(await resolver.ResolveAsync(Query, CancellationToken.None));

        Assert.DoesNotContain(LogLevel.Warning, logger.Levels);
        Assert.Contains(LogLevel.Debug, logger.Levels);
    }
}
