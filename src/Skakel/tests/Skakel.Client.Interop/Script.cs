using System.Diagnostics.CodeAnalysis;

namespace Skakel.Client.Interop;

/// <summary>
/// How a scenario talks to the Rust test that runs it. It prints one line per fact: <c>OK text</c> for a
/// check that held, <c>CODE</c> and <c>CREDENTIALS</c> for what the Rust side needs, and <c>WAIT action</c>
/// when the Rust side has to do something on the server. After a WAIT the scenario reads a line from
/// standard input, which is <c>DONE</c> once the action is done.
/// </summary>
internal static class Script
{
    public static void Say(string line)
    {
        Console.Out.WriteLine(line);
        Console.Out.Flush();
    }

    public static void Wait(string action)
    {
        Say($"WAIT {action}");
        var answer = Console.In.ReadLine();
        if (answer != "DONE")
        {
            throw new CheckFailedException($"The Rust test did not finish '{action}' (got '{answer}').");
        }
    }

    public static void Check([DoesNotReturnIf(false)] bool held, string what)
    {
        if (!held)
        {
            throw new CheckFailedException(what);
        }

        Say($"OK {what}");
    }

    public static async Task<SkakelException> Fails(Func<Task> call, SkakelFailureKind kind, string what)
    {
        try
        {
            await call();
        }
        catch (SkakelException ex)
        {
            Check(ex.Failure.Kind == kind, $"{what}: {kind} (got {ex.Failure.Kind})");
            return ex;
        }

        throw new CheckFailedException($"{what}: expected {kind}, but it worked.");
    }
}

internal sealed class CheckFailedException(string message) : Exception(message);

/// <summary>What an event raised, for a scenario to wait on.</summary>
internal sealed class Recorder<T>
{
    private readonly List<T> _seen = [];
    private int _arrivals;

    public Task Record(T value)
    {
        lock (_seen)
        {
            _seen.Add(value);
        }

        Interlocked.Increment(ref _arrivals);
        return Task.CompletedTask;
    }

    /// <summary>The first value, among those seen so far and after, that satisfies <paramref name="match"/>.</summary>
    public async Task<T> WaitAsync(Func<T, bool> match, TimeSpan? timeout = null)
    {
        using var limit = new CancellationTokenSource(timeout ?? TimeSpan.FromSeconds(30));
        while (true)
        {
            var seen = Volatile.Read(ref _arrivals);
            lock (_seen)
            {
                foreach (var value in _seen)
                {
                    if (match(value))
                    {
                        return value;
                    }
                }
            }

            while (Volatile.Read(ref _arrivals) == seen)
            {
                await Task.Delay(10, limit.Token);
            }
        }
    }
}
