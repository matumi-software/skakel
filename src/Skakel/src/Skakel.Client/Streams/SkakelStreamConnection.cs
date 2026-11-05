using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net.WebSockets;
using Skakel.Protocol;

namespace Skakel.Client;

/// <summary>
/// An open stream: one WebSocket that carries one thing. Binary frames carry its data and text frames
/// its control messages, one JSON object each. Both ends ping every 15 seconds and give up after 30
/// without an answer.
/// </summary>
public sealed class SkakelStreamConnection : IAsyncDisposable, IDisposable
{
    /// <summary>How long a close may wait for the server's answer.</summary>
    private static readonly TimeSpan CloseTimeout = TimeSpan.FromSeconds(2);

    private readonly HttpResponseMessage _upgrade;

    internal SkakelStreamConnection(string type, WebSocket webSocket, HttpResponseMessage upgrade)
    {
        Type = type;
        WebSocket = webSocket;
        _upgrade = upgrade;
    }

    /// <summary>The stream type.</summary>
    public string Type { get; }

    /// <summary>The WebSocket. Send and receive on it; close it with <see cref="CloseAsync"/>.</summary>
    public WebSocket WebSocket { get; }

    /// <summary>Why the stream ended, once it has: the server's close code as a reason. Null while it is open.</summary>
    public SkakelStreamClose? Close => WebSocket.State switch
    {
        WebSocketState.CloseReceived or WebSocketState.Closed when WebSocket.CloseStatus is { } code => SkakelStreamClose.From((int)code, WebSocket.CloseStatusDescription),
        WebSocketState.Closed or WebSocketState.Aborted => SkakelStreamClose.From(null, null),
        _ => null,
    };

    /// <summary>Closes the stream normally and waits briefly for the server to answer. Never throws for a stream that is already gone.</summary>
    /// <param name="cancellationToken">Stops waiting for the server's answer.</param>
    public async Task CloseAsync(CancellationToken cancellationToken = default)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(CloseTimeout);
        try
        {
            if (WebSocket.State is WebSocketState.Open or WebSocketState.CloseReceived)
            {
                await WebSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, null, timeout.Token);
            }
        }
        catch (Exception ex) when (ex is WebSocketException or OperationCanceledException or ObjectDisposedException or IOException)
        {
            // The server or the connection went away first; the stream is over either way.
            WebSocket.Abort();
        }
    }

    /// <summary>Lets go of the stream without a close frame, if it is still open.</summary>
    public void Dispose()
    {
        WebSocket.Dispose();
        _upgrade.Dispose();
    }

    /// <summary>Closes the stream normally, then lets go of it.</summary>
    public async ValueTask DisposeAsync()
    {
        await CloseAsync();
        Dispose();
    }
}

/// <summary>Why a stream ended, by its close code.</summary>
public enum SkakelStreamCloseReason
{
    /// <summary>1000: closed normally.</summary>
    Normal,

    /// <summary>4001: the client was revoked.</summary>
    Revoked,

    /// <summary>4002: the client's secret was rotated.</summary>
    Rotated,

    /// <summary>4003: the server is stopping, or no longer serves this type.</summary>
    ServerStopping,

    /// <summary>4004: the target went away, such as a device that was unplugged.</summary>
    TargetGone,

    /// <summary>4100 to 4999: a code the stream type defines. <see cref="SkakelStreamClose.Code"/> says which.</summary>
    TypeDefined,

    /// <summary>The connection ended without a close frame, or a peer stopped answering pings.</summary>
    ConnectionLost,

    /// <summary>Any other code.</summary>
    Other,
}

/// <summary>How a stream ended.</summary>
/// <param name="Reason">The close code as a reason a client acts on.</param>
/// <param name="Code">The close code, or null when there was no close frame.</param>
/// <param name="Description">The server's reason text, for the log only.</param>
public sealed record SkakelStreamClose(SkakelStreamCloseReason Reason, int? Code, string? Description)
{
    /// <summary>What to tell a person, in fixed wording.</summary>
    public string Message => Reason switch
    {
        SkakelStreamCloseReason.Normal => "The stream closed.",
        SkakelStreamCloseReason.Revoked => SkakelFailure.Of(SkakelFailureKind.Revoked).Message,
        SkakelStreamCloseReason.Rotated => SkakelFailure.Of(SkakelFailureKind.Rotated).Message,
        SkakelStreamCloseReason.ServerStopping => "The server stopped serving this stream.",
        SkakelStreamCloseReason.TargetGone => "What the stream was for went away on the server.",
        SkakelStreamCloseReason.ConnectionLost => SkakelFailure.Of(SkakelFailureKind.ConnectionLost).Message,
        _ => string.Create(CultureInfo.InvariantCulture, $"The server closed the stream with code {Code}."),
    };

    /// <summary>The close for a code, or for none when the connection just ended.</summary>
    /// <param name="code">The close code, or null.</param>
    /// <param name="description">The reason text.</param>
    public static SkakelStreamClose From(int? code, string? description) => new(code switch
    {
        null or 1006 => SkakelStreamCloseReason.ConnectionLost,
        SkakelCloseCodes.Normal => SkakelStreamCloseReason.Normal,
        SkakelCloseCodes.Revoked => SkakelStreamCloseReason.Revoked,
        SkakelCloseCodes.Rotated => SkakelStreamCloseReason.Rotated,
        SkakelCloseCodes.Stopping => SkakelStreamCloseReason.ServerStopping,
        SkakelCloseCodes.TargetGone => SkakelStreamCloseReason.TargetGone,
        >= SkakelCloseCodes.FirstTypeDefined and <= SkakelCloseCodes.LastTypeDefined => SkakelStreamCloseReason.TypeDefined,
        _ => SkakelStreamCloseReason.Other,
    }, code, description);
}

/// <summary>Why the server refused to open a stream, by the HTTP status it answered before the upgrade.</summary>
public enum SkakelStreamRefusalReason
{
    /// <summary>400: the request was not a WebSocket upgrade.</summary>
    NotAnUpgrade,

    /// <summary>401: no token, an expired one, or one from an older generation.</summary>
    Unauthorized,

    /// <summary>404: the server has no such type, or no such target.</summary>
    NotFound,

    /// <summary>409: the target is in use. <see cref="SkakelStreamRefusal.Message"/> names who holds it, when the app allows that.</summary>
    InUse,

    /// <summary>422: the query string is not what the type expects.</summary>
    InvalidQuery,

    /// <summary>Any other status.</summary>
    Other,
}

/// <summary>The server refused to open a stream.</summary>
/// <param name="Status">The HTTP status.</param>
/// <param name="Reason">The status as a reason.</param>
/// <param name="Message">The problem's <c>detail</c>, which the server wrote for a person, or fixed wording when it sent none.</param>
public sealed record SkakelStreamRefusal(int Status, SkakelStreamRefusalReason Reason, string Message)
{
    internal static SkakelStreamRefusal From(int status, string? detail)
    {
        var reason = status switch
        {
            400 => SkakelStreamRefusalReason.NotAnUpgrade,
            401 => SkakelStreamRefusalReason.Unauthorized,
            404 => SkakelStreamRefusalReason.NotFound,
            409 => SkakelStreamRefusalReason.InUse,
            422 => SkakelStreamRefusalReason.InvalidQuery,
            _ => SkakelStreamRefusalReason.Other,
        };
        var message = !string.IsNullOrWhiteSpace(detail) ? detail.Trim() : reason switch
        {
            SkakelStreamRefusalReason.Unauthorized => SkakelFailure.Of(SkakelFailureKind.ClientUnknown).Message,
            SkakelStreamRefusalReason.NotFound => "The server has no such stream or target.",
            SkakelStreamRefusalReason.InUse => "Someone else is using it.",
            SkakelStreamRefusalReason.InvalidQuery => "The server did not understand what the stream was asked for.",
            _ => string.Create(CultureInfo.InvariantCulture, $"The server refused the stream ({status})."),
        };
        return new SkakelStreamRefusal(status, reason, message);
    }
}

/// <summary>What opening a stream gave: the stream, or the server's refusal.</summary>
/// <typeparam name="T">The stream.</typeparam>
public sealed class SkakelOpenResult<T>
    where T : class
{
    private SkakelOpenResult(T? stream, SkakelStreamRefusal? refusal)
    {
        Stream = stream;
        Refusal = refusal;
    }

    /// <summary>The stream, when it opened.</summary>
    public T? Stream { get; }

    /// <summary>Why the server refused, when it did.</summary>
    public SkakelStreamRefusal? Refusal { get; }

    /// <summary>True when the stream opened.</summary>
    [MemberNotNullWhen(true, nameof(Stream))]
    [MemberNotNullWhen(false, nameof(Refusal))]
    public bool IsOpen => Stream is not null;

    internal static SkakelOpenResult<T> Opened(T stream) => new(stream, null);

    internal static SkakelOpenResult<T> Refused(SkakelStreamRefusal refusal) => new(null, refusal);
}
