using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Skakel.Protocol;

namespace Skakel.Client;

/// <summary>
/// Gets client-credentials access tokens from one server and reuses each until shortly before it
/// expires. One per link, shared by the hub, the streams and the app's own requests.
/// </summary>
internal sealed class TokenClient(HttpClient http, Func<Uri> server, SkakelCredentials credentials, TimeProvider time) : IDisposable
{
    /// <summary>A token is renewed this long before it expires, so one handed out still has time to be used.</summary>
    internal static readonly TimeSpan RenewBefore = TimeSpan.FromMinutes(1);

    /// <summary>The shortest lifetime a token is taken to have, whatever the server says, so a server cannot set off a stream of renewals.</summary>
    internal static readonly TimeSpan MinLifetime = TimeSpan.FromMinutes(2);

    /// <summary>The longest lifetime a token is taken to have: the protocol's 30 minutes.</summary>
    internal static readonly TimeSpan MaxLifetime = SkakelProtocol.AccessTokenLifetime;

    private readonly SemaphoreSlim _gate = new(1, 1);
    private (string Token, DateTimeOffset ExpiresAt)? _cached;

    /// <summary>A token that has at least a minute left, and when it expires.</summary>
    /// <exception cref="TokenRequestException">The server refused the request.</exception>
    public async Task<(string Token, DateTimeOffset ExpiresAt)> GetAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (_cached is { } cached && cached.ExpiresAt - RenewBefore > time.GetUtcNow())
            {
                return cached;
            }

            using var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = credentials.ClientId,
                ["client_secret"] = credentials.ClientSecret,
            });
            using var response = await http.PostAsync(new Uri(server(), SkakelProtocol.TokenPath), form, cancellationToken);
            var body = await ReadBodyAsync(response, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                throw new TokenRequestException(body?.Error ?? $"http_{(int)response.StatusCode}", response.StatusCode);
            }

            if (body?.AccessToken is not { Length: > 0 } token)
            {
                throw new InvalidDataException("The token answer has no access token.");
            }

            var fresh = (token, time.GetUtcNow() + Lifetime(body.ExpiresIn));
            _cached = fresh;
            return fresh;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Drops the cached token, as after the server refused it, unless a newer one replaced it already.</summary>
    public void Forget(string token)
    {
        if (_cached is { } cached && cached.Token == token)
        {
            _cached = null;
        }
    }

    public void Dispose() => _gate.Dispose();

    /// <summary>The server's <c>expires_in</c>, held to 2 to 30 minutes; five minutes when it gave none.</summary>
    internal static TimeSpan Lifetime(int? expiresIn) =>
        TimeSpan.FromSeconds(Math.Clamp(expiresIn ?? 300, (int)MinLifetime.TotalSeconds, (int)MaxLifetime.TotalSeconds));

    /// <summary>The JSON body, or null when there is none or it is not JSON, such as a proxy's error page.</summary>
    private static async Task<TokenResponse?> ReadBodyAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        try
        {
            return await response.Content.ReadFromJsonAsync<TokenResponse>(cancellationToken);
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException)
        {
            return null;
        }
    }

    private sealed record TokenResponse(
        [property: JsonPropertyName("access_token")] string? AccessToken,
        [property: JsonPropertyName("expires_in")] int? ExpiresIn,
        [property: JsonPropertyName("error")] string? Error);
}
