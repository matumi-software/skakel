using Microsoft.Extensions.Logging;

namespace Skakel.Client;

/// <summary>
/// Raises an async event the same way everywhere: every handler runs, one at a time and in the order
/// they subscribed, and a handler that throws is logged without stopping the ones after it.
/// </summary>
/// <remarks>
/// Invoking a multicast <c>Func&lt;T, Task&gt;</c> directly awaits only the last handler's task and
/// loses the others' exceptions, so declare the event as usual and raise it with
/// <c>await Changed.RaiseAsync(value, logger)</c>.
/// </remarks>
internal static partial class AsyncEvents
{
    public static async Task RaiseAsync<T>(this Func<T, Task>? handlers, T value, ILogger logger)
    {
        await handlers.TryRaiseAsync(value, logger);
    }

    /// <summary>The same, and false when a handler threw, for a caller that acts only once every handler took the value.</summary>
    public static async Task<bool> TryRaiseAsync<T>(this Func<T, Task>? handlers, T value, ILogger logger)
    {
        if (handlers is null)
        {
            return true;
        }

        var ok = true;
        foreach (var handler in handlers.GetInvocationList().Cast<Func<T, Task>>())
        {
            try
            {
                await handler(value);
            }
            catch (Exception ex)
            {
                ok = false;
                LogHandlerFailed(logger, handler.Method.DeclaringType?.Name ?? "?", typeof(T).Name, ex);
            }
        }

        return ok;
    }

    [LoggerMessage(Level = LogLevel.Error, Message = "{Handler} failed while handling {Value}")]
    private static partial void LogHandlerFailed(ILogger logger, string handler, string value, Exception exception);
}
