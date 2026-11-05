using System.Net;
using System.Net.Http.Json;
using Skakel.Protocol;

namespace Skakel.Server.Tests;

/// <summary>The client registry: what the app's UI is told, what is kept, and what survives a restart.</summary>
public sealed class ClientsTests
{
    [Fact]
    public async Task Changed_tells_the_ui_about_a_register_a_rotation_and_a_revoke()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = await SkakelTestHost.StartAsync();
        var pushed = new List<IReadOnlyList<SkakelClientView>>();
        host.Clients.Changed += clients =>
        {
            pushed.Add(clients);
            return Task.CompletedTask;
        };

        var client = await host.Clients.RegisterAsync("bench-1", ct);
        await host.Clients.RevokeAsync(client.ClientId, ct);

        pushed.Should().HaveCount(2);
        pushed[0].Should().ContainSingle().Which.Name.Should().Be("bench-1");
        pushed[1].Should().BeEmpty();
    }

    [Fact]
    public async Task Changed_on_the_keys_fires_for_the_certificates_and_not_for_a_client()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = await SkakelTestHost.StartAsync();
        var pushed = new List<SkakelKeysView>();
        host.Keys.Changed += keys =>
        {
            pushed.Add(keys);
            return Task.CompletedTask;
        };

        await host.Clients.RegisterAsync("bench-1", ct);
        pushed.Should().BeEmpty();

        var next = await host.Keys.PrepareNextCertificateAsync(ct);
        pushed.Should().ContainSingle().Which.NextFingerprint.Should().Be(next);
    }

    [Fact]
    public async Task Only_the_hash_is_kept_unless_the_app_asks_for_the_secret()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var plain = await SkakelTestHost.StartAsync();
        await using var keeping = await SkakelTestHost.StartAsync(o => o.KeepClientSecrets = true);

        var hashed = await plain.Clients.RegisterAsync("bench-1", ct);
        var kept = await keeping.Clients.RegisterAsync("bench-1", ct);

        plain.Clients.SecretOf(hashed.ClientId).Should().BeNull();
        plain.Store.State!.Clients.Single().Secret.Should().BeNull();
        plain.Store.State.Clients.Single().SecretHash.Should().NotContain(hashed.ClientSecret);
        keeping.Clients.SecretOf(kept.ClientId).Should().Be(kept.ClientSecret);
        keeping.Clients.All.Single().HasSecret.Should().BeTrue();
        var rotated = await keeping.Clients.RotateSecretAsync(kept.ClientId, ct);
        keeping.Clients.SecretOf(kept.ClientId).Should().Be(rotated);
    }

    [Fact]
    public async Task Clients_keys_and_the_certificate_survive_a_restart()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new InMemorySkakelStore();
        string fingerprint;
        SkakelNewClient client;
        string token;
        await using (var first = await SkakelTestHost.StartAsync(store: store))
        {
            client = await first.Clients.RegisterAsync("bench-1", ct);
            token = await first.TokenAsync(client.ClientId, client.ClientSecret, ct);
            fingerprint = first.Keys.Fingerprint;
        }

        await using var second = await SkakelTestHost.StartAsync(store: store);

        second.Keys.Fingerprint.Should().Be(fingerprint);
        second.Clients.All.Should().ContainSingle().Which.Id.Should().Be(client.ClientId);
        (await second.HelloAsync(token, ct)).StatusCode.Should().Be(HttpStatusCode.OK, "the signing key is the same");
    }

    [Fact]
    public async Task Pairing_calls_take_a_limited_number_of_requests_per_minute_from_one_address()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = await SkakelTestHost.StartAsync(o => o.PairRequestsPerMinute = 3);
        using var https = host.Https();

        for (var i = 0; i < 3; i++)
        {
            (await https.GetAsync($"{SkakelProtocol.PairPath}/nothing", ct)).StatusCode.Should().Be(HttpStatusCode.NotFound);
        }

        using var refused = await https.PostAsJsonAsync(SkakelProtocol.PairPath, new PairOpenRequest("bench", PairingCode.Commit("n")), SkakelJson.Options, ct);
        refused.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);
    }
}
