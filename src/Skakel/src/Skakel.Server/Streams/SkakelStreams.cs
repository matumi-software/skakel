using System.Net.WebSockets;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Skakel.Protocol;

namespace Skakel.Server;

/// <summary>
/// Decides whether a stream may open, before the WebSocket upgrade: checks the query string, finds the
/// target and takes it, then accepts with what runs inside the stream, or refuses.
/// </summary>
/// <param name="request">The client's request, its token already checked.</param>
public delegate ValueTask<SkakelStreamResult> SkakelStreamHandler(SkakelStreamRequest request);

/// <summary>A client asking to open a stream. Its token and generation have been checked.</summary>
public sealed class SkakelStreamRequest
{
    internal SkakelStreamRequest(HttpContext httpContext, string type, string clientId, string clientName)
    {
        HttpContext = httpContext;
        Type = type;
        ClientId = clientId;
        ClientName = clientName;
    }

    /// <summary>The HTTP request, before the upgrade.</summary>
    public HttpContext HttpContext { get; }

    /// <summary>The stream type.</summary>
    public string Type { get; }

    /// <summary>The client asking.</summary>
    public string ClientId { get; }

    /// <summary>What the client is called.</summary>
    public string ClientName { get; }

    /// <summary>The query string, which says what the stream is for. The type defines it.</summary>
    public IQueryCollection Query => HttpContext.Request.Query;

    /// <summary>Cancelled when the client goes away before the stream opens.</summary>
    public CancellationToken RequestAborted => HttpContext.RequestAborted;
}

/// <summary>What a <see cref="SkakelStreamHandler"/> decided.</summary>
public abstract class SkakelStreamResult
{
    private protected SkakelStreamResult()
    {
    }

    /// <summary>Opens the stream and runs <paramref name="run"/> with it. The stream closes normally when it returns, unless it was closed already.</summary>
    /// <param name="run">What runs inside the stream.</param>
    public static SkakelStreamResult Accept(Func<SkakelStreamSession, Task> run)
    {
        ArgumentNullException.ThrowIfNull(run);
        return new Accepted(run);
    }

    /// <summary>404: there is no such target.</summary>
    /// <param name="detail">What was not found, for a person.</param>
    public static SkakelStreamResult NotFound(string detail) => new Refused(StatusCodes.Status404NotFound, detail);

    /// <summary>409: the target is in use. Name who holds it, when the app allows that.</summary>
    /// <param name="detail">Who or what holds it, for a person.</param>
    public static SkakelStreamResult InUse(string detail) => new Refused(StatusCodes.Status409Conflict, detail);

    /// <summary>422: the query string is not what the type expects.</summary>
    /// <param name="detail">What it should be, for a person.</param>
    public static SkakelStreamResult Invalid(string detail) => new Refused(StatusCodes.Status422UnprocessableEntity, detail);

    internal sealed class Accepted(Func<SkakelStreamSession, Task> run) : SkakelStreamResult
    {
        public Func<SkakelStreamSession, Task> Run { get; } = run;
    }

    internal sealed class Refused(int status, string detail) : SkakelStreamResult
    {
        public int Status { get; } = status;

        public string Detail { get; } = detail;
    }
}

/// <summary>
/// An open stream. Binary frames carry its data and text frames its control messages, one JSON object
/// each. Both ends ping every 15 seconds and give up after 30 without an answer.
/// </summary>
/// <remarks>
/// When the server ends the stream (the client was revoked or rotated, or the server stops), the close
/// frame with its code goes out first. A handler waiting to receive then sees the client's answer; if it
/// has not returned a second later, <see cref="Ending"/> is cancelled, and five seconds after that the
/// socket is aborted.
/// </remarks>
public sealed partial class SkakelStreamSession : IDisposable
{
    /// <summary>How long sending a close frame may take.</summary>
    internal static readonly TimeSpan CloseTimeout = TimeSpan.FromSeconds(2);

    /// <summary>How long the client has to answer the server's close frame before the handler is told to stop.</summary>
    internal static readonly TimeSpan AnswerTimeout = TimeSpan.FromSeconds(1);

    /// <summary>How long a handler has to return after it was told to stop, before the socket is aborted.</summary>
    internal static readonly TimeSpan ReturnTimeout = TimeSpan.FromSeconds(5);

    private readonly CancellationTokenSource _ending;
    private readonly TaskCompletionSource _returned = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly ILogger _logger;
    private int _closing;

    internal SkakelStreamSession(WebSocket webSocket, string type, string clientId, ILogger logger, CancellationToken requestAborted)
    {
        WebSocket = webSocket;
        Type = type;
        ClientId = clientId;
        _logger = logger;
        _ending = CancellationTokenSource.CreateLinkedTokenSource(requestAborted);
    }

    /// <summary>The WebSocket. Send and receive on it; close it through <see cref="CloseAsync"/>.</summary>
    public WebSocket WebSocket { get; }

    /// <summary>The stream type.</summary>
    public string Type { get; }

    /// <summary>The client the stream belongs to.</summary>
    public string ClientId { get; }

    /// <summary>Cancelled when the stream is ending: it was closed, the server ended it, or the connection went away.</summary>
    public CancellationToken Ending => _ending.Token;

    /// <summary>
    /// Closes the stream with a code a client can act on, such as <see cref="SkakelCloseCodes.TargetGone"/>
    /// or one the type defines (4100 to 4999), then cancels <see cref="Ending"/>. Only the first close counts.
    /// </summary>
    /// <param name="code">The close code.</param>
    /// <param name="reason">A short reason, at most 123 bytes of UTF-8.</param>
    public async Task CloseAsync(int code, string? reason = null)
    {
        await SendCloseAsync(code, reason);
        await _ending.CancelAsync();
    }

    /// <summary>Stops the token.</summary>
    public void Dispose() => _ending.Dispose();

    /// <summary>
    /// The server ends the stream. The close frame goes out first, so the client has the code at once.
    /// The handler then has a moment to see the client's answer, is told through <see cref="Ending"/>,
    /// and is aborted if it still does not return.
    /// </summary>
    internal async Task EndAsync(string reason)
    {
        await SendCloseAsync(SkakelCloseCodes.For(reason), reason);
        if (await Task.WhenAny(_returned.Task, Task.Delay(AnswerTimeout)) == _returned.Task)
        {
            return;
        }

        try
        {
            await _ending.CancelAsync();
        }
        catch (ObjectDisposedException)
        {
            // The handler returned and the stream is gone already.
            return;
        }

        if (await Task.WhenAny(_returned.Task, Task.Delay(ReturnTimeout)) != _returned.Task)
        {
            WebSocket.Abort();
        }
    }

    /// <summary>After the handler returned: closes normally if nobody closed yet, and waits briefly for the client's answer.</summary>
    internal async Task FinishAsync()
    {
        _returned.TrySetResult();
        await SendCloseAsync(SkakelCloseCodes.Normal, null);
        if (WebSocket.State == WebSocketState.CloseSent)
        {
            try
            {
                using var timeout = new CancellationTokenSource(CloseTimeout);
                var buffer = new byte[256];
                while ((await WebSocket.ReceiveAsync(buffer, timeout.Token)).MessageType != WebSocketMessageType.Close)
                {
                    // What the client still had in flight; the stream is over.
                }
            }
            catch (Exception ex) when (ex is WebSocketException or OperationCanceledException or ObjectDisposedException or IOException)
            {
                // The client did not answer the close; the connection ends anyway.
            }
        }
    }

    /// <summary>Sends the close frame, once.</summary>
    private async Task SendCloseAsync(int code, string? reason)
    {
        if (Interlocked.Exchange(ref _closing, 1) == 1)
        {
            return;
        }

        try
        {
            if (WebSocket.State is WebSocketState.Open or WebSocketState.CloseReceived)
            {
                using var timeout = new CancellationTokenSource(CloseTimeout);
                await WebSocket.CloseOutputAsync((WebSocketCloseStatus)code, reason, timeout.Token);
            }
        }
        catch (Exception ex) when (ex is WebSocketException or OperationCanceledException or ObjectDisposedException or IOException)
        {
            LogCloseFailed(Type, ClientId, ex.Message);
        }
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "Could not close a {Type} stream of client {ClientId}: {Reason}")]
    private partial void LogCloseFailed(string type, string clientId, string reason);
}
