using System.Net;
using System.Threading.RateLimiting;
using Microsoft.Extensions.Options;

namespace Skakel.Server;

/// <summary>
/// The limits on the endpoints anyone may call. Tokens and pairing each have a fixed one-minute window
/// per address, counted per full address; <see cref="SkakelRequestGate"/> applies them before anything
/// reads the request. Failed token requests also have a window per client. Kept by Skakel itself rather
/// than the app's rate limiter, so they hold however the app sets up its own.
/// </summary>
internal sealed class SkakelRateLimits : IDisposable
{
    /// <summary>Failed token requests allowed per minute for one client, from all addresses together.</summary>
    internal const int TokenFailuresPerClientPerMinute = 10;

    private readonly PartitionedRateLimiter<string> _token;
    private readonly PartitionedRateLimiter<string> _pair;
    private readonly PartitionedRateLimiter<string> _tokenFailures;

    public SkakelRateLimits(IOptions<SkakelServerOptions> options)
    {
        _token = Window(options.Value.TokenRequestsPerMinute);
        _pair = Window(options.Value.PairRequestsPerMinute);
        _tokenFailures = Window(TokenFailuresPerClientPerMinute);
    }

    /// <summary>Takes a token request from this address, when it has some of its allowance left.</summary>
    public bool TryToken(IPAddress? from) => TryTake(_token, SkakelPairing.AddressKey(from));

    /// <summary>Takes a pairing request from this address, when it has some of its allowance left.</summary>
    public bool TryPair(IPAddress? from) => TryTake(_pair, SkakelPairing.AddressKey(from));

    /// <summary>True while the client has had too many failed token requests this minute.</summary>
    public bool TooManyFailures(string clientId)
    {
        // Zero permits only asks whether any are left.
        using var lease = _tokenFailures.AttemptAcquire(clientId, 0);
        return !lease.IsAcquired;
    }

    /// <summary>Counts a failed token request against a registered client.</summary>
    public void CountFailure(string clientId) => _tokenFailures.AttemptAcquire(clientId).Dispose();

    public void Dispose()
    {
        _token.Dispose();
        _pair.Dispose();
        _tokenFailures.Dispose();
    }

    private static bool TryTake(PartitionedRateLimiter<string> limiter, string key)
    {
        using var lease = limiter.AttemptAcquire(key);
        return lease.IsAcquired;
    }

    private static PartitionedRateLimiter<string> Window(int permits) =>
        PartitionedRateLimiter.Create<string, string>(key => RateLimitPartition.GetFixedWindowLimiter(key, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = permits,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
        }));
}
