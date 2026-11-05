using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Skakel.Protocol;

namespace Skakel.Server.Tests;

/// <summary>Tokens at /skakel/v1/token, the generation in them, and what a revoke or rotation does to them.</summary>
public sealed class TokenTests : IAsyncLifetime
{
    private SkakelTestHost _host = null!;

    public async ValueTask InitializeAsync() => _host = await SkakelTestHost.StartAsync(o => o.TokenRequestsPerMinute = 5);

    public ValueTask DisposeAsync() => _host.DisposeAsync();

    [Fact]
    public async Task Token_endpoint_issues_a_30_minute_token_with_the_client_and_its_generation()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await _host.Clients.RegisterAsync("bench-1", ct);

        using var response = await _host.RequestTokenAsync(client.ClientId, client.ClientSecret, ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(ct);
        body.GetProperty("expires_in").GetInt32().Should().BeCloseTo(1800, 5);
        var token = body.GetProperty("access_token").GetString()!;
        var claims = Part(token, 1);
        claims.GetProperty("sub").GetString().Should().Be(client.ClientId);
        claims.GetProperty(SkakelProtocol.GenerationClaim).GetString().Should().Be("1");
        Part(token, 0).GetProperty("kid").GetString().Should().Be(_host.Keys.View.SigningKeyId);
    }

    [Fact]
    public async Task Token_endpoint_answers_a_wrong_secret_with_the_oauth_error_and_nothing_more()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await _host.Clients.RegisterAsync("bench-1", ct);

        using var wrong = await _host.RequestTokenAsync(client.ClientId, "not-the-secret", ct);
        using var unknown = await _host.RequestTokenAsync("client-nobody", client.ClientSecret, ct);

        wrong.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await wrong.Content.ReadFromJsonAsync<JsonElement>(ct)).GetProperty("error").GetString().Should().Be("invalid_client");
        (await wrong.Content.ReadAsStringAsync(ct)).Should().Be(await unknown.Content.ReadAsStringAsync(ct), "a wrong secret and an unknown client look the same");
    }

    [Fact]
    public async Task Hello_answers_the_server_and_the_client_for_a_current_token()
    {
        var ct = TestContext.Current.CancellationToken;
        var (client, token) = await _host.NewClientWithTokenAsync("bench-1", ct);

        using var hello = await _host.HelloAsync(token, ct);

        hello.StatusCode.Should().Be(HttpStatusCode.OK);
        (await hello.Content.ReadFromJsonAsync<SkakelHello>(SkakelJson.Options, ct)).Should().Be(new SkakelHello("bench", client.ClientId));
    }

    [Fact]
    public async Task Rotating_the_secret_refuses_every_token_from_before_and_the_old_secret()
    {
        var ct = TestContext.Current.CancellationToken;
        var (client, old) = await _host.NewClientWithTokenAsync("bench-1", ct);

        var secret = await _host.Clients.RotateSecretAsync(client.ClientId, ct);

        (await _host.HelloAsync(old, ct)).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await _host.RequestTokenAsync(client.ClientId, client.ClientSecret, ct)).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        var fresh = await _host.TokenAsync(client.ClientId, secret!, ct);
        Part(fresh, 1).GetProperty(SkakelProtocol.GenerationClaim).GetString().Should().Be("2");
        (await _host.HelloAsync(fresh, ct)).StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Revoking_a_client_refuses_its_tokens_at_once()
    {
        var ct = TestContext.Current.CancellationToken;
        var (client, token) = await _host.NewClientWithTokenAsync("bench-1", ct);

        (await _host.Clients.RevokeAsync(client.ClientId, ct)).Should().BeTrue();

        (await _host.HelloAsync(token, ct)).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await _host.RequestTokenAsync(client.ClientId, client.ClientSecret, ct)).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await _host.Clients.RevokeAsync(client.ClientId, ct)).Should().BeFalse();
    }

    [Fact]
    public async Task Token_endpoint_takes_a_limited_number_of_requests_per_minute_from_one_address()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await _host.Clients.RegisterAsync("bench-1", ct);

        for (var i = 0; i < 5; i++)
        {
            (await _host.RequestTokenAsync(client.ClientId, "wrong", ct)).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        using var refused = await _host.RequestTokenAsync(client.ClientId, client.ClientSecret, ct);
        refused.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);
        refused.Content.Headers.ContentType!.MediaType.Should().Be(SkakelProtocol.ProblemContentType);
    }

    [Fact]
    public async Task A_token_sent_over_plain_http_is_refused()
    {
        var ct = TestContext.Current.CancellationToken;
        var (_, token) = await _host.NewClientWithTokenAsync("bench-1", ct);
        using var http = _host.PlainHttp();
        using var request = new HttpRequestMessage(HttpMethod.Get, SkakelProtocol.HelloPath);
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

        using var response = await http.SendAsync(request, ct);

        response.IsSuccessStatusCode.Should().BeFalse();
    }

    private static JsonElement Part(string token, int index)
    {
        var part = token.Split('.')[index].Replace('-', '+').Replace('_', '/');
        part = part.PadRight(part.Length + ((4 - (part.Length % 4)) % 4), '=');
        return JsonDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(part))).RootElement;
    }
}
