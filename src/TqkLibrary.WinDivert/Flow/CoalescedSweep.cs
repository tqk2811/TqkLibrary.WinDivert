using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace TqkLibrary.WinDivert.Flow;

/// <summary>
/// Runs an expensive sweep (the kernel-table reconcile) on one background worker and lets any
/// number of callers wait for it, sharing sweeps between them.
/// </summary>
/// <remarks>
/// The guarantee each caller gets: the sweep that completes its task STARTED after the caller
/// asked. That is what the NAT stage needs — the flow it is asking about was registered by
/// connect() before its SYN was captured, so any sweep that begins after the request sees it — and
/// it is why a sweep already in flight cannot answer a newcomer.
///
/// Generations make that cheap: every request takes the next number; the worker notes the newest
/// number before it begins a sweep and, when the sweep is done, completes exactly the waiters at
/// or below it. Requests that arrived during the sweep wait for one more, which serves all of them
/// at once. So a burst of N SYNs costs one or two sweeps instead of N.
/// </remarks>
public sealed class CoalescedSweep
{
    private readonly Action _sweep;
    private readonly Action<Exception>? _onError;
    private readonly object _lock = new object();
    private readonly List<Waiter> _waiters = new List<Waiter>();
    private long _requested;
    private bool _running;

    private readonly struct Waiter
    {
        public readonly long Generation;
        public readonly TaskCompletionSource<bool> Completion;
        public Waiter(long generation, TaskCompletionSource<bool> completion)
        {
            Generation = generation;
            Completion = completion;
        }
    }

    /// <param name="sweep">The work itself. Runs on a thread-pool thread, one call at a time.</param>
    /// <param name="onError">Told about a sweep that threw. Waiters are completed either way.</param>
    public CoalescedSweep(Action sweep, Action<Exception>? onError = null)
    {
        _sweep = sweep ?? throw new ArgumentNullException(nameof(sweep));
        _onError = onError;
    }

    /// <summary>
    /// Completes once a sweep that started after this call has finished (or failed — the caller
    /// re-checks whatever it was waiting for either way). Cancelling stops the wait, not the sweep.
    /// </summary>
    public Task RequestAsync(CancellationToken cancellationToken = default)
    {
        if (cancellationToken.IsCancellationRequested)
            return Task.FromCanceled(cancellationToken);

        var completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        bool startWorker;
        lock (_lock)
        {
            _waiters.Add(new Waiter(++_requested, completion));
            startWorker = !_running;
            _running = true;
        }
        if (startWorker) _ = Task.Run(WorkerLoop);

        if (!cancellationToken.CanBeCanceled) return completion.Task;
        // The waiter stays in the list after a cancel; completing an already-cancelled source on
        // the next sweep is a harmless no-op.
        CancellationTokenRegistration registration = cancellationToken.Register(
            static state => ((TaskCompletionSource<bool>)state!).TrySetCanceled(), completion);
        completion.Task.ContinueWith(
            static (_, state) => ((CancellationTokenRegistration)state!).Dispose(), registration,
            CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        return completion.Task;
    }

    private void WorkerLoop()
    {
        while (true)
        {
            long startGeneration;
            lock (_lock) startGeneration = _requested;

            try { _sweep(); }
            catch (Exception ex)
            {
                try { _onError?.Invoke(ex); } catch { }
            }

            List<TaskCompletionSource<bool>> done = new List<TaskCompletionSource<bool>>();
            bool again;
            lock (_lock)
            {
                for (int i = _waiters.Count - 1; i >= 0; i--)
                {
                    if (_waiters[i].Generation > startGeneration) continue;
                    done.Add(_waiters[i].Completion);
                    _waiters.RemoveAt(i);
                }
                again = _requested != startGeneration;
                if (!again) _running = false;
            }
            foreach (TaskCompletionSource<bool> completion in done) completion.TrySetResult(true);
            if (!again) return;
        }
    }
}
