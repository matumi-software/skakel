using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Skakel.Server;

/// <summary>
/// The per-address limits on the endpoints anyone may call: tokens, and pairing. A fixed one-minute
/// window per address, counted as pairing counts addresses (one IPv4 address or one IPv6 /64). Kept by
/// Skakel itself rather than the app's rate limiter, so they hold however the app sets up its own.
/// </summary>
internal sealed class SkakelRateLimits : IDisposable
{
    private readonly PartitionedRateLimiter<string> _token;
    private readonly PartitionedRateLimiter<string> _pair;

    public SkakelRateLimits(IOptions<SkakelServerOptions> options)
    {
        _token = Window(options.Value.TokenRequestsPerMinute);
        _pair = Window(options.Value.PairRequestsPerMinute);
    }

    /// <summary>Lets a token request through when its address has some of its allowance left.</summary>
    public IEndpointFilter Token => new Filter(_token);

    /// <summary>Lets a pairing request through when its address has some of its allowance left.</summary>
    public IEndpointFilter Pair => new Filter(_pair);

    public void Dispose()
    {
        _token.Dispose();
        _pair.Dispose();
    }

    private static PartitionedRateLimiter<string> Window(int permits) =>
        PartitionedRateLimiter.Create<string, string>(key => RateLimitPartition.GetFixedWindowLimiter(key, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = permits,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
        }));

    private sealed class Filter(PartitionedRateLimiter<string> limiter) : IEndpointFilter
    {
        public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
        {
            using var lease = limiter.AttemptAcquire(SkakelPairing.AddressKey(context.HttpContext.Connection.RemoteIpAddress));
            return lease.IsAcquired
                ? await next(context)
                : TypedResults.Problem(statusCode: StatusCodes.Status429TooManyRequests, detail: "Too many requests from this address. Wait a minute and try again.");
        }
    }
}
