using System.Net.WebSockets;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using Skakel.Protocol;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Skakel.Server;

/// <summary>
/// What <c>MapSkakel</c> mapped. Conventions added here apply to all of it; each part has its own
/// builder too. Streams the app maps with <c>MapSkakelStream</c> are not part of it.
/// </summary>
public sealed class SkakelEndpointConventionBuilder : IEndpointConventionBuilder
{
    private readonly IEndpointConventionBuilder _all;

    internal SkakelEndpointConventionBuilder(IEndpointConventionBuilder all, IEndpointConventionBuilder info, IEndpointConventionBuilder pairing, IEndpointConventionBuilder token, IEndpointConventionBuilder hello, IEndpointConventionBuilder unknownStreams)
    {
        _all = all;
        Info = info;
        Pairing = pairing;
        Token = token;
        Hello = hello;
        UnknownStreams = unknownStreams;
    }

    /// <summary><c>GET /skakel/info</c>.</summary>
    public IEndpointConventionBuilder Info { get; }

    /// <summary>The pairing endpoints under <c>/skakel/v1/pair</c>.</summary>
    public IEndpointConventionBuilder Pairing { get; }

    /// <summary><c>POST /skakel/v1/token</c>.</summary>
    public IEndpointConventionBuilder Token { get; }

    /// <summary><c>GET /skakel/v1/hello</c>.</summary>
    public IEndpointConventionBuilder Hello { get; }

    /// <summary>The answer for a stream type nobody mapped.</summary>
    public IEndpointConventionBuilder UnknownStreams { get; }

    /// <inheritdoc />
    public void Add(Action<EndpointBuilder> convention) => _all.Add(convention);

    /// <inheritdoc />
    public void Finally(Action<EndpointBuilder> finallyConvention) => _all.Finally(finallyConvention);
}

/// <summary>The endpoints a Skakel client calls.</summary>
internal static partial class SkakelEndpoints
{
    public static SkakelEndpointConventionBuilder Map(IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        // The per-address limits on pairing and tokens, and the cap on their bodies, run before routing, in SkakelRequestGate.
        var all = endpoints.MapGroup("/skakel");

        var info = all.MapGet("/info", (IOptions<SkakelServerOptions> options) =>
            Json(new SkakelInfo(options.Value.Name, options.Value.App, SkakelProtocol.Versions)));

        var v1 = all.MapGroup($"/v{SkakelProtocol.Version}");
        var pairing = MapPairing(v1.MapGroup("/pair"));
        var token = v1.MapPost("/token", IssueTokenAsync);

        var hello = v1.MapGet("/hello", (HttpContext http, IOptions<SkakelServerOptions> options) =>
            Json(new SkakelHello(options.Value.Name, http.User.GetSkakelClientId()!))).RequireSkakelClient();

        // Literal routes win over this one, so it only answers types nobody mapped. The token is checked first, so
        // nobody learns which types there are without one.
        var unknown = v1.Map("/streams/{type}", (HttpContext http, string type) => OpenStreamAsync(http, type, null));

        return new SkakelEndpointConventionBuilder(all, info, pairing, token, hello, unknown);
    }

    public static IEndpointConventionBuilder MapStream(IEndpointRouteBuilder endpoints, string type, SkakelStreamHandler handler) =>
        // Map rather than MapGet: a WebSocket over HTTP/2 arrives as CONNECT.
        // A Delegate, not a RequestDelegate, so the result is written.
        endpoints.Map($"{SkakelProtocol.StreamsPath}/{type}", (Delegate)((HttpContext http) => OpenStreamAsync(http, type, handler)));

    /// <summary>
    /// The pairing exchange a client runs before it has credentials: no token, HTTPS only. See
    /// <see cref="SkakelPairing"/>.
    /// </summary>
    private static RouteGroupBuilder MapPairing(RouteGroupBuilder pair)
    {
        pair.AddEndpointFilter(async (context, next) => context.HttpContext.Request.IsHttps
            ? await next(context)
            : Problem(StatusCodes.Status400BadRequest, "Pair over HTTPS, pinned to the server's certificate."));

        pair.MapPost("/", async Task<IResult> (SkakelPairing pairing, HttpContext http) =>
        {
            if (await ReadAsync<PairOpenRequest>(http) is not { } request)
            {
                return Problem(StatusCodes.Status400BadRequest, "Send the client's name and commitment as JSON.");
            }

            var name = ClientNames.Clean(request.ClientName);
            if (name.Length == 0 || name.Length > SkakelPairing.MaxClientNameLength)
            {
                return Problem(StatusCodes.Status400BadRequest, $"Give the client a name of 1 to {SkakelPairing.MaxClientNameLength} characters.");
            }

            if (request.Commitment is not { Length: 64 } commitment || !commitment.All(Uri.IsHexDigit))
            {
                return Problem(StatusCodes.Status400BadRequest, "The commitment must be the 64 hex digits of a SHA-256 hash.");
            }

            return pairing.Open(name, commitment, http.Connection.RemoteIpAddress) is { } opened
                ? Json(opened)
                : Problem(StatusCodes.Status429TooManyRequests, "This server is taking no more pairing requests from here for now. Try again in a few minutes.");
        });

        pair.MapPost("/{requestId}/reveal", async Task<IResult> (string requestId, SkakelPairing pairing, HttpContext http) =>
            await ReadAsync<PairRevealRequest>(http) is { ClientNonce: { Length: > 0 } nonce }
                ? await pairing.RevealAsync(requestId, nonce) switch
                {
                    SkakelReveal.Revealed => TypedResults.NoContent(),
                    SkakelReveal.Full => Problem(StatusCodes.Status429TooManyRequests, "This server has as many pairing requests waiting as a person can look at. Try again in a few minutes."),
                    _ => NoSuchRequest(),
                }
                : NoSuchRequest());

        pair.MapGet("/{requestId}", async Task<IResult> (string requestId, SkakelPairing pairing, HttpContext http) =>
            await pairing.PollAsync(requestId, http.Request.Headers[SkakelProtocol.PairTokenHeader]) is { } poll ? Json(poll) : NoSuchRequest());

        pair.MapDelete("/{requestId}", async Task<IResult> (string requestId, SkakelPairing pairing, HttpContext http) =>
            await pairing.WithdrawAsync(requestId, http.Request.Headers[SkakelProtocol.PairTokenHeader]) ? TypedResults.NoContent() : NoSuchRequest());

        return pair;

        static IResult NoSuchRequest() => Problem(StatusCodes.Status404NotFound, "There is no such pairing request waiting, or the poll token is wrong.");
    }

    /// <summary>
    /// OAuth 2.0 client credentials. OpenIddict has read and checked the request by now; this checks the
    /// secret and issues the token for the generation it was checked at. A registered client that had too
    /// many wrong secrets this minute gets 429 without its secret being checked.
    /// </summary>
    private static IResult IssueTokenAsync(HttpContext http, ServerState state, SkakelRateLimits limits)
    {
        var request = http.GetOpenIddictServerRequest() ?? throw new InvalidOperationException("The token request did not pass through OpenIddict.");
        if (!request.IsClientCredentialsGrantType())
        {
            return SkakelAuth.Refuse(Errors.UnsupportedGrantType, "Only the client_credentials grant is supported.");
        }

        // Only registered clients are counted, so made-up IDs cannot fill the limiter.
        if (string.IsNullOrEmpty(request.ClientId) || string.IsNullOrEmpty(request.ClientSecret) || state.Find(request.ClientId) is null)
        {
            return SkakelAuth.Refuse(Errors.InvalidClient, "The client ID or secret is wrong, or the client was revoked.");
        }

        if (limits.TooManyFailures(request.ClientId))
        {
            return Problem(StatusCodes.Status429TooManyRequests, "Too many failed requests for this client. Wait a minute and try again.");
        }

        if (state.Validate(request.ClientId, request.ClientSecret) is { } generation)
        {
            return SkakelAuth.Issue(request.ClientId, generation);
        }

        limits.CountFailure(request.ClientId);
        return SkakelAuth.Refuse(Errors.InvalidClient, "The client ID or secret is wrong, or the client was revoked.");
    }

    /// <summary>
    /// Opens a stream: checks the token and the client's generation, lets the type's handler check the
    /// query and the target, then upgrades and runs the handler's stream until it ends. Every refusal is
    /// an HTTP answer with a problem body, before the upgrade.
    /// </summary>
    private static async Task<IResult> OpenStreamAsync(HttpContext http, string type, SkakelStreamHandler? handler)
    {
        var services = http.RequestServices;
        var state = services.GetRequiredService<ServerState>();
        var auth = await http.AuthenticateAsync(SkakelServerDefaults.AuthenticationScheme);
        if (!http.Request.IsHttps || auth.Principal is not { } user || !state.IsCurrent(user))
        {
            return Problem(StatusCodes.Status401Unauthorized, "Open streams over HTTPS with a current token. This one is missing or has expired, or the client was revoked or its secret rotated since it was issued.");
        }

        http.User = user;
        var clientId = user.GetSkakelClientId()!;
        if (handler is null)
        {
            return Problem(StatusCodes.Status404NotFound, $"This server has no stream type '{type}'.");
        }

        if (!http.WebSockets.IsWebSocketRequest)
        {
            return Problem(StatusCodes.Status400BadRequest, "A stream opens with a WebSocket upgrade.");
        }

        var result = await handler(new SkakelStreamRequest(http, type, clientId, state.Find(clientId)?.Name ?? clientId));
        if (result is SkakelStreamResult.Refused refused)
        {
            return Problem(refused.Status, refused.Detail);
        }

        var run = ((SkakelStreamResult.Accepted)result).Run;
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger<SkakelStreamSession>();
        var socket = await http.WebSockets.AcceptWebSocketAsync(new WebSocketAcceptContext
        {
            KeepAliveInterval = SkakelProtocol.StreamKeepAliveInterval,
            KeepAliveTimeout = SkakelProtocol.StreamKeepAliveTimeout,
        });
        using var session = new SkakelStreamSession(socket, type, clientId, logger, http.RequestAborted);
        using (services.GetRequiredService<SkakelSessions>().AddStream(clientId, user.GetSkakelGeneration()!.Value, session.EndAsync))
        {
            try
            {
                await run(session);
            }
            catch (Exception ex) when (ex is OperationCanceledException or WebSocketException or IOException or ObjectDisposedException)
            {
                LogStreamEnded(logger, type, clientId, ex.Message);
            }
            catch (Exception ex)
            {
                // One bad stream must not take the host down, and it must leave a trace.
                LogStreamFailed(logger, type, clientId, ex);
            }

            await session.FinishAsync();
        }

        socket.Dispose();
        return TypedResults.Empty;
    }

    private static ProblemHttpResult Problem(int status, string detail) => TypedResults.Problem(statusCode: status, detail: detail);

    /// <summary>Skakel's own JSON, whatever the app set for its own endpoints, so the wire format stays the protocol's.</summary>
    private static JsonHttpResult<T> Json<T>(T value) => TypedResults.Json(value, SkakelJson.Options);

    /// <summary>A JSON body read the protocol's way, or null when there is none or it is not JSON of that shape.</summary>
    private static async Task<T?> ReadAsync<T>(HttpContext http)
        where T : class
    {
        if (!http.Request.HasJsonContentType())
        {
            return null;
        }

        try
        {
            return await http.Request.ReadFromJsonAsync<T>(SkakelJson.Options, http.RequestAborted);
        }
        catch (System.Text.Json.JsonException)
        {
            return null;
        }
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "A {Type} stream of client {ClientId} ended: {Reason}")]
    private static partial void LogStreamEnded(ILogger logger, string type, string clientId, string reason);

    [LoggerMessage(Level = LogLevel.Warning, Message = "A {Type} stream of client {ClientId} failed")]
    private static partial void LogStreamFailed(ILogger logger, string type, string clientId, Exception exception);
}
