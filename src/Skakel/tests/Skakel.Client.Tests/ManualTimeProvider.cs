namespace Skakel.Client.Tests;

/// <summary>
/// A clock that moves only when a test says so. Timers fire in order, on the calling thread, as the
/// clock passes them, so code driven by <see cref="TimeProvider"/> can be tested without waiting.
/// </summary>
internal sealed class ManualTimeProvider : TimeProvider
{
    private readonly Lock _gate = new();
    private readonly List<ManualTimer> _timers = [];
    private readonly List<(int Count, TaskCompletionSource Done)> _waiters = [];
    private DateTimeOffset _now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public override DateTimeOffset GetUtcNow()
    {
        lock (_gate)
        {
            return _now;
        }
    }

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var timer = new ManualTimer(this, callback, state);
        timer.Change(dueTime, period);
        return timer;
    }

    /// <summary>Completes once at least <paramref name="count"/> timers are armed, so a test knows the code under test is waiting.</summary>
    public Task WhenTimersAsync(int count)
    {
        lock (_gate)
        {
            if (_timers.Count >= count)
            {
                return Task.CompletedTask;
            }

            var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            _waiters.Add((count, done));
            return done.Task;
        }
    }

    public void Advance(TimeSpan by)
    {
        DateTimeOffset target;
        lock (_gate)
        {
            target = _now + by;
        }

        while (true)
        {
            ManualTimer? next;
            lock (_gate)
            {
                next = _timers.Where(t => t.Due <= target).OrderBy(t => t.Due).FirstOrDefault();
                if (next is null)
                {
                    _now = target;
                    return;
                }

                _now = next.Due > _now ? next.Due : _now;
                if (next.Period > TimeSpan.Zero)
                {
                    next.Due += next.Period;
                }
                else
                {
                    _timers.Remove(next);
                }
            }

            next.Fire();
        }
    }

    private void Arm(ManualTimer timer, TimeSpan dueTime, TimeSpan period)
    {
        List<TaskCompletionSource> ready = [];
        lock (_gate)
        {
            _timers.Remove(timer);
            if (dueTime != Timeout.InfiniteTimeSpan)
            {
                timer.Due = _now + dueTime;
                timer.Period = period == Timeout.InfiniteTimeSpan ? TimeSpan.Zero : period;
                _timers.Add(timer);
                foreach (var waiter in _waiters.Where(w => _timers.Count >= w.Count).ToList())
                {
                    _waiters.Remove(waiter);
                    ready.Add(waiter.Done);
                }
            }
        }

        foreach (var done in ready)
        {
            done.TrySetResult();
        }
    }

    private void Disarm(ManualTimer timer)
    {
        lock (_gate)
        {
            _timers.Remove(timer);
        }
    }

    private sealed class ManualTimer(ManualTimeProvider owner, TimerCallback callback, object? state) : ITimer
    {
        public DateTimeOffset Due { get; set; }

        public TimeSpan Period { get; set; }

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            owner.Arm(this, dueTime, period);
            return true;
        }

        public void Fire() => callback(state);

        public void Dispose() => owner.Disarm(this);

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
