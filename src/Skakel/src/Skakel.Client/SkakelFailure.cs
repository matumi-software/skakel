using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text.Json;
using Skakel.Protocol;

namespace Skakel.Client;

/// <summary>What went wrong talking to a server. A fixed set: an app shows <see cref="SkakelFailure.Message"/> and acts on the kind.</summary>
public enum SkakelFailureKind
{
    /// <summary>Nothing answered at the server's address: refused, timed out, no route, or a name that does not resolve.</summary>
    Unreachable,

    /// <summary>The server presented a certificate the client does not trust.</summary>
    CertificateMismatch,

    /// <summary>The server refused the client ID or secret.</summary>
    RejectedCredentials,

    /// <summary>The server issued a token but then refused it: it no longer knows the client.</summary>
    ClientUnknown,

    /// <summary>The server and the client have no protocol version in common.</summary>
    VersionMismatch,

    /// <summary>Something answered, but not the way a Skakel server does.</summary>
    UnexpectedAnswer,

    /// <summary>The server is taking no more requests from this address for now.</summary>
    TooManyRequests,

    /// <summary>The server revoked the client. Its credentials are gone.</summary>
    Revoked,

    /// <summary>The server gave the client a new secret, so the one it holds no longer works.</summary>
    Rotated,

    /// <summary>The server is stopping.</summary>
    ServerStopping,

    /// <summary>The connection to the server ended without the server saying why.</summary>
    ConnectionLost,

    /// <summary>The link is not connected, so the call could not be made.</summary>
    NotConnected,

    /// <summary>The server refused the pairing request, or the code was typed wrong three times.</summary>
    PairingDenied,

    /// <summary>The pairing request ran out before anyone typed the code.</summary>
    PairingExpired,
}

/// <summary>
/// A failure as a person sees it: one of a fixed set of kinds, each with fixed wording. The detail of
/// what went wrong goes to the log, never into the message, so the wording cannot be used to probe
/// addresses and ports.
/// </summary>
public sealed record SkakelFailure
{
    private SkakelFailure(SkakelFailureKind kind, string message)
    {
        Kind = kind;
        Message = message;
    }

    /// <summary>What kind of failure.</summary>
    public SkakelFailureKind Kind { get; }

    /// <summary>The kind as a camelCase word, such as <c>certificateMismatch</c>, for an app's API or UI.</summary>
    public string Code => JsonNamingPolicy.CamelCase.ConvertName(Kind.ToString());

    /// <summary>What to tell a person.</summary>
    public string Message { get; }

    /// <summary>The failure of this kind with its fixed wording.</summary>
    /// <param name="kind">The kind. For <see cref="SkakelFailureKind.VersionMismatch"/>, <see cref="VersionMismatch"/> names the versions.</param>
    public static SkakelFailure Of(SkakelFailureKind kind) => new(kind, kind switch
    {
        SkakelFailureKind.Unreachable => "Could not reach the server. Check the address and that the server is running.",
        SkakelFailureKind.CertificateMismatch => "The server's certificate does not match the one this app trusts. If the server has a new certificate, pair with it again.",
        SkakelFailureKind.RejectedCredentials => "The server refused this client's ID or secret. Pair with the server again.",
        SkakelFailureKind.ClientUnknown => "The server accepted the token but no longer knows this client. Pair with the server again.",
        SkakelFailureKind.VersionMismatch => "This server and this app speak different versions of Skakel. Update the older one.",
        SkakelFailureKind.UnexpectedAnswer => "The server did not answer like a Skakel server.",
        SkakelFailureKind.TooManyRequests => "The server is taking no more requests from here for now. Try again in a few minutes.",
        SkakelFailureKind.Revoked => "The server revoked this client. Pair with the server again.",
        SkakelFailureKind.Rotated => "The server gave this client a new secret. Pair with the server again.",
        SkakelFailureKind.ServerStopping => "The server is stopping.",
        SkakelFailureKind.ConnectionLost => "The connection to the server was lost.",
        SkakelFailureKind.NotConnected => "Not connected to the server.",
        SkakelFailureKind.PairingDenied => "The server refused the pairing request.",
        SkakelFailureKind.PairingExpired => "Nobody typed the code on the server in time. Start again.",
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Not a Skakel failure."),
    });

    /// <summary>
    /// The server speaks none of this client's protocol versions, worded with both sides' versions and
    /// which one to update, such as "This server speaks Skakel 2 and this app speaks Skakel 1. Update the app."
    /// </summary>
    /// <param name="serverVersions">The versions the server listed.</param>
    public static SkakelFailure VersionMismatch(IReadOnlyCollection<int> serverVersions)
    {
        ArgumentNullException.ThrowIfNull(serverVersions);
        if (serverVersions.Count == 0)
        {
            return Of(SkakelFailureKind.VersionMismatch);
        }

        var update = serverVersions.Max() > SkakelProtocol.Versions.Max() ? "the app" : "the server";
        return new(SkakelFailureKind.VersionMismatch, $"This server speaks Skakel {List(serverVersions)} and this app speaks Skakel {List(SkakelProtocol.Versions)}. Update {update}.");
    }

    /// <summary>Versions as people write them: <c>1</c>, <c>1 and 2</c>, <c>1, 2 and 3</c>.</summary>
    private static string List(IEnumerable<int> versions)
    {
        var words = versions.Distinct().Order().Select(v => v.ToString(CultureInfo.InvariantCulture)).ToList();
        return words.Count == 1 ? words[0] : $"{string.Join(", ", words[..^1])} and {words[^1]}";
    }
}

/// <summary>A call to a server failed. <see cref="Exception.Message"/> is the failure's fixed wording; the cause is in <see cref="Exception.InnerException"/>, for the log.</summary>
public sealed class SkakelException : Exception
{
    /// <summary>A failure with no cause beyond itself.</summary>
    /// <param name="failure">What went wrong.</param>
    public SkakelException(SkakelFailure failure)
        : this(failure, null)
    {
    }

    /// <summary>A failure and what caused it.</summary>
    /// <param name="failure">What went wrong.</param>
    /// <param name="innerException">The cause, for the log.</param>
    public SkakelException(SkakelFailure failure, Exception? innerException)
        : base((failure ?? throw new ArgumentNullException(nameof(failure))).Message, innerException)
    {
        Failure = failure;
    }

    /// <summary>What went wrong.</summary>
    public SkakelFailure Failure { get; }

    internal SkakelException(SkakelFailureKind kind, Exception? innerException = null)
        : this(SkakelFailure.Of(kind), innerException)
    {
    }
}

/// <summary>The server refused a token request, with OAuth's error code and the HTTP status.</summary>
internal sealed class TokenRequestException(string error, HttpStatusCode status)
    : Exception($"The token request failed: {error} ({(int)status}).")
{
    public string Error { get; } = error;

    public HttpStatusCode Status { get; } = status;
}

/// <summary>Turns what can go wrong talking to a server into one of the fixed failures.</summary>
internal static class Failures
{
    public static SkakelFailure From(Exception ex)
    {
        var chain = Chain(ex).ToList();
        if (chain.OfType<SkakelException>().FirstOrDefault() is { } skakel)
        {
            return skakel.Failure;
        }

        // A handshake that failed is a certificate we do not trust, wherever it surfaced.
        if (chain.Any(e => e is AuthenticationException))
        {
            return SkakelFailure.Of(SkakelFailureKind.CertificateMismatch);
        }

        foreach (var e in chain)
        {
            switch (e)
            {
                case TokenRequestException { Error: "invalid_client" }:
                    return SkakelFailure.Of(SkakelFailureKind.RejectedCredentials);
                case TokenRequestException { Status: HttpStatusCode.TooManyRequests }:
                case HttpRequestException { StatusCode: HttpStatusCode.TooManyRequests }:
                    return SkakelFailure.Of(SkakelFailureKind.TooManyRequests);
                case HttpRequestException { StatusCode: HttpStatusCode.Unauthorized }:
                    return SkakelFailure.Of(SkakelFailureKind.ClientUnknown);
                case TokenRequestException:
                case HttpRequestException { StatusCode: not null }:
                case JsonException:
                case InvalidDataException:
                    return SkakelFailure.Of(SkakelFailureKind.UnexpectedAnswer);
            }
        }

        return SkakelFailure.Of(SkakelFailureKind.Unreachable);
    }

    /// <summary>The failure as an exception to throw, keeping the cause for the log.</summary>
    public static SkakelException Exception(Exception ex) => ex as SkakelException ?? new SkakelException(From(ex), ex);

    /// <summary>
    /// True when nothing answered at the server's address: the connection was refused or timed out, there
    /// was no route, or the name no longer resolves. A server that answered, with a certificate that does
    /// not match or by refusing the credentials, is not unreachable.
    /// </summary>
    public static bool IsUnreachable(Exception ex)
    {
        foreach (var e in Chain(ex))
        {
            switch (e)
            {
                case AuthenticationException or TokenRequestException:
                    return false;
                case SkakelException { Failure.Kind: SkakelFailureKind.Unreachable } skakel when skakel.InnerException is null:
                case HttpRequestException { HttpRequestError: HttpRequestError.ConnectionError or HttpRequestError.NameResolutionError }:
                case TimeoutException:
                case SocketException
                {
                    SocketErrorCode: SocketError.ConnectionRefused or SocketError.TimedOut or SocketError.HostUnreachable
                        or SocketError.NetworkUnreachable or SocketError.HostDown or SocketError.HostNotFound or SocketError.NoData,
                }:
                    return true;
            }
        }

        return false;
    }

    private static IEnumerable<Exception> Chain(Exception ex)
    {
        for (var e = ex; e is not null; e = e.InnerException)
        {
            yield return e;
            if (e is AggregateException aggregate)
            {
                foreach (var inner in aggregate.InnerExceptions.SelectMany(Chain))
                {
                    yield return inner;
                }
            }
        }
    }
}
