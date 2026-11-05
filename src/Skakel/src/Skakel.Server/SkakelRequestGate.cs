using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Skakel.Protocol;

namespace Skakel.Server;

/// <summary>
/// The first thing a token or pairing request meets: the per-address limit, then a cap on the body.
/// Both run before anything reads the request. The token server reads, checks and logs a whole token
/// request during authentication, which runs before any endpoint filter, so a limit there came too
/// late to spare the server that work.
/// </summary>
/// <remarks>
/// A startup filter puts it at the very start of the app's pipeline (see <see cref="Startup"/>), ahead
/// of routing, authentication and whatever the app adds, so it holds however the app orders its own
/// middleware. It knows the requests by their paths, which the protocol fixes.
/// </remarks>
internal sealed class SkakelRequestGate(RequestDelegate next, SkakelRateLimits limits)
{
    /// <summary>The largest body a token or pairing request may have. A real one is a few hundred bytes.</summary>
    internal const long MaxBodyBytes = 4 * 1024;

    public Task InvokeAsync(HttpContext http)
    {
        var path = http.Request.Path;
        var token = path.StartsWithSegments(SkakelProtocol.TokenPath, StringComparison.OrdinalIgnoreCase);
        if (!token && !path.StartsWithSegments(SkakelProtocol.PairPath, StringComparison.OrdinalIgnoreCase))
        {
            return next(http);
        }

        var from = http.Connection.RemoteIpAddress;
        if (!(token ? limits.TryToken(from) : limits.TryPair(from)))
        {
            return TypedResults.Problem(statusCode: StatusCodes.Status429TooManyRequests, detail: "Too many requests from this address. Wait a minute and try again.").ExecuteAsync(http);
        }

        if (http.Request.ContentLength > MaxBodyBytes)
        {
            return TypedResults.Problem(statusCode: StatusCodes.Status413PayloadTooLarge, detail: $"The body is over {MaxBodyBytes} bytes.").ExecuteAsync(http);
        }

        // A body sent without a length is cut off by the server once it passes the cap.
        if (http.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } size)
        {
            size.MaxRequestBodySize = MaxBodyBytes;
        }

        return next(http);
    }

    /// <summary>Puts the gate at the start of the app's pipeline.</summary>
    internal sealed class Startup : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.UseMiddleware<SkakelRequestGate>();
            next(app);
        };
    }
}
