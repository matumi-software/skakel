using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
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

    [Fact]
    public async Task Token_endpoint_refuses_a_body_over_the_limit_before_reading_it()
    {
        var body = Encoding.ASCII.GetBytes("grant_type=client_credentials&client_id=a&client_secret=b&x=" + new string('A', 64 * 1024));

        var answer = await _host.SendFromAsync(IPAddress.Parse("10.0.0.9"), "POST", SkakelProtocol.TokenPath, "application/x-www-form-urlencoded", body);

        answer.Response.StatusCode.Should().Be(StatusCodes.Status413PayloadTooLarge);
    }

    [Fact]
    public async Task Token_endpoint_counts_a_request_against_the_limit_before_reading_it()
    {
        var from = IPAddress.Parse("10.0.0.9");
        var malformed = Encoding.ASCII.GetBytes("client_id=a&client_secret=b");
        for (var i = 0; i < 5; i++)
        {
            (await _host.SendFromAsync(from, "POST", SkakelProtocol.TokenPath, "application/x-www-form-urlencoded", malformed)).Response.StatusCode.Should().Be(StatusCodes.Status400BadRequest);
        }

        (await _host.SendFromAsync(from, "POST", SkakelProtocol.TokenPath, "application/x-www-form-urlencoded", malformed)).Response.StatusCode
            .Should().Be(StatusCodes.Status429TooManyRequests, "requests the token server turns away still count");
    }

    [Theory]
    [InlineData("2001:db8:1:1::a", "2001:db8:1:1::b")]
    [InlineData("fe80::a", "fe80::b")]
    public async Task Token_endpoint_counts_each_ipv6_address_on_its_own(string noisy, string quiet)
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await _host.Clients.RegisterAsync("bench-1", ct);
        for (var i = 0; i < 5; i++)
        {
            await _host.RequestTokenFromAsync(IPAddress.Parse(noisy), client.ClientId, "wrong");
        }

        (await _host.RequestTokenFromAsync(IPAddress.Parse(noisy), client.ClientId, client.ClientSecret)).Should().Be(StatusCodes.Status429TooManyRequests);
        (await _host.RequestTokenFromAsync(IPAddress.Parse(quiet), client.ClientId, client.ClientSecret)).Should().Be(StatusCodes.Status200OK, "another host on the same network has its own allowance");
    }

    [Fact]
    public async Task Token_endpoint_refuses_a_client_after_too_many_wrong_secrets_from_any_address()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = await SkakelTestHost.StartAsync(o => o.TokenRequestsPerMinute = 100);
        var client = await host.Clients.RegisterAsync("bench-1", ct);
        var other = await host.Clients.RegisterAsync("bench-2", ct);

        for (var i = 0; i < SkakelRateLimits.TokenFailuresPerClientPerMinute; i++)
        {
            (await host.RequestTokenFromAsync(IPAddress.Parse($"10.3.0.{i + 1}"), client.ClientId, "wrong")).Should().Be(StatusCodes.Status401Unauthorized);
        }

        (await host.RequestTokenFromAsync(IPAddress.Parse("10.3.1.1"), client.ClientId, client.ClientSecret)).Should().Be(StatusCodes.Status429TooManyRequests, "the client had its share of wrong secrets this minute");
        (await host.RequestTokenFromAsync(IPAddress.Parse("10.3.1.1"), other.ClientId, other.ClientSecret)).Should().Be(StatusCodes.Status200OK, "another client is not held up");
    }

    [Fact]
    public async Task A_token_works_under_every_name_and_address_of_the_server()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await _host.Clients.RegisterAsync("bench-1", ct);
        var body = Encoding.ASCII.GetBytes($"grant_type=client_credentials&client_id={client.ClientId}&client_secret={client.ClientSecret}");
        var issued = await _host.SendFromAsync(IPAddress.Parse("10.0.0.9"), "POST", SkakelProtocol.TokenPath, "application/x-www-form-urlencoded", body, "192.168.1.5:5240");
        issued.Response.StatusCode.Should().Be(StatusCodes.Status200OK);
        var token = (await JsonDocument.ParseAsync(issued.Response.Body, cancellationToken: ct)).RootElement.GetProperty("access_token").GetString()!;

        Part(token, 1).GetProperty("iss").GetString().Should().Be("https://skakel.invalid/");
        foreach (var host in new[] { "192.168.1.5:5240", "pi-lab.local:5240", "10.0.0.1" })
        {
            var hello = await _host.Server.SendAsync(context =>
            {
                context.Request.Scheme = "https";
                context.Request.Host = new HostString(host);
                context.Request.Path = SkakelProtocol.HelloPath;
                context.Request.Headers.Authorization = $"Bearer {token}";
            }, ct);
            hello.Response.StatusCode.Should().Be(StatusCodes.Status200OK, $"the server is also {host}");
        }
    }

    [Theory]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/jwks")]
    public async Task The_token_server_s_discovery_documents_are_not_served(string path)
    {
        using var https = _host.Https();

        using var response = await https.GetAsync(path, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    private static JsonElement Part(string token, int index)
    {
        var part = token.Split('.')[index].Replace('-', '+').Replace('_', '/');
        part = part.PadRight(part.Length + ((4 - (part.Length % 4)) % 4), '=');
        return JsonDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(part))).RootElement;
    }
}
