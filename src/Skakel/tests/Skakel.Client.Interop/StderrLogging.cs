using Microsoft.Extensions.Logging;

namespace Skakel.Client.Interop;

/// <summary>
/// Writes the client's log to standard error when the environment variable <c>SKAKEL_INTEROP_LOG</c> is set,
/// for finding out why a scenario failed against a server that is not the .NET one.
/// </summary>
internal sealed class StderrLoggerProvider : ILoggerProvider, ILogger
{
    public static SkakelClientOptions Options() => new()
    {
        LoggerFactory = Environment.GetEnvironmentVariable("SKAKEL_INTEROP_LOG") is null
            ? null
            : LoggerFactory.Create(builder => builder.SetMinimumLevel(LogLevel.Debug).AddProvider(new StderrLoggerProvider())),
    };

    public ILogger CreateLogger(string categoryName) => this;

    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
        Console.Error.WriteLine($"LOG {logLevel}: {formatter(state, exception)}{(exception is null ? "" : $" ({exception.GetType().Name}: {exception.Message})")}");

    public void Dispose()
    {
    }
}
