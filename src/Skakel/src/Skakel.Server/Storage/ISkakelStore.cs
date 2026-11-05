namespace Skakel.Server;

/// <summary>
/// Where a Skakel server keeps its <see cref="SkakelState"/>. The app supplies it, so the state lives
/// wherever the app keeps its own secrets. Skakel loads it once at start and saves the whole state
/// after every change, one save at a time, and applies a change only once its save returned.
/// </summary>
public interface ISkakelStore
{
    /// <summary>The state saved last, or null on the first start, when Skakel makes a new one and saves it.</summary>
    ValueTask<SkakelState?> LoadAsync(CancellationToken cancellationToken);

    /// <summary>Saves the state, replacing what was there. Throw when it could not be saved; the change is then not applied.</summary>
    ValueTask SaveAsync(SkakelState state, CancellationToken cancellationToken);
}

/// <summary>
/// Keeps the state in memory only, so a restart of the process forgets every client. For tests, and
/// for trying Skakel out. A second server given the same instance starts where the first left off.
/// </summary>
public sealed class InMemorySkakelStore : ISkakelStore
{
    private SkakelState? _state;

    /// <summary>What was saved last.</summary>
    public SkakelState? State => Volatile.Read(ref _state);

    /// <inheritdoc />
    public ValueTask<SkakelState?> LoadAsync(CancellationToken cancellationToken) => ValueTask.FromResult(State);

    /// <inheritdoc />
    public ValueTask SaveAsync(SkakelState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(state);
        Volatile.Write(ref _state, state);
        return ValueTask.CompletedTask;
    }
}
