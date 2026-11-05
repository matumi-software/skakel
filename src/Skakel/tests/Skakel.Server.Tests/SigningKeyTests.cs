using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Skakel.Protocol;

namespace Skakel.Server.Tests;

/// <summary>Rotating the token signing key, on the state against a manual clock.</summary>
public sealed class SigningKeyTests : IAsyncLifetime
{
    private readonly ManualTimeProvider _time = new();
    private readonly InMemorySkakelStore _store = new();
    private ServerState _state = null!;

    public async ValueTask InitializeAsync() => _state = await StartAsync();

    public ValueTask DisposeAsync()
    {
        _state.Dispose();
        return ValueTask.CompletedTask;
    }

    [Fact]
    public async Task RotateSigningKeyAsync_signs_with_a_new_key_and_still_accepts_the_old_one()
    {
        var ct = TestContext.Current.CancellationToken;
        var first = _state.SigningKey.KeyId;

        var id = await _state.RotateSigningKeyAsync(ct);

        _state.SigningKey.KeyId.Should().Be(id).And.NotBe(first);
        _state.ValidationKeys.Select(k => k.KeyId).Should().Equal(id, first);
        _state.KeysView.SigningKeyId.Should().Be(id);
        _state.KeysView.RetiredKeysUntil.Should().Be(_time.GetUtcNow() + SkakelProtocol.AccessTokenLifetime + ServerState.RetiredKeyMargin);
    }

    [Fact]
    public async Task RotateSigningKeyAsync_tells_the_token_server_to_take_the_new_keys()
    {
        var ct = TestContext.Current.CancellationToken;
        var token = _state.GetChangeToken();

        await _state.RotateSigningKeyAsync(ct);

        token.HasChanged.Should().BeTrue();
        _state.GetChangeToken().HasChanged.Should().BeFalse();
    }

    [Fact]
    public async Task A_replaced_key_is_dropped_once_every_token_it_signed_has_expired()
    {
        var ct = TestContext.Current.CancellationToken;
        var id = await _state.RotateSigningKeyAsync(ct);

        _time.Advance(SkakelProtocol.AccessTokenLifetime);
        _state.ValidationKeys.Should().HaveCount(2, "a token signed just before the rotation is still valid");

        _time.Advance(ServerState.RetiredKeyMargin);

        await EventuallyAsync(() => _state.ValidationKeys.Count == 1, ct);
        _state.ValidationKeys.Single().KeyId.Should().Be(id);
        _state.KeysView.RetiredKeysUntil.Should().BeNull();
        _store.State!.RetiredSigningKeys.Should().BeEmpty();
    }

    [Fact]
    public async Task A_restart_during_the_overlap_keeps_both_keys()
    {
        var ct = TestContext.Current.CancellationToken;
        var first = _state.SigningKey.KeyId;
        var id = await _state.RotateSigningKeyAsync(ct);

        _state.Dispose();
        _state = await StartAsync();

        _state.SigningKey.KeyId.Should().Be(id);
        _state.ValidationKeys.Select(k => k.KeyId).Should().Equal(id, first);
    }

    [Fact]
    public async Task A_restart_after_the_overlap_drops_the_old_key()
    {
        var ct = TestContext.Current.CancellationToken;
        var id = await _state.RotateSigningKeyAsync(ct);
        _state.Dispose();

        _time.Advance(SkakelProtocol.AccessTokenLifetime + ServerState.RetiredKeyMargin);
        _state = await StartAsync();

        _state.ValidationKeys.Select(k => k.KeyId).Should().Equal(id);
    }

    [Fact]
    public async Task A_token_signed_before_a_rotation_still_works_and_new_tokens_carry_the_new_key()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = await SkakelTestHost.StartAsync();
        var client = await host.Clients.RegisterAsync("bench-1", ct);
        var before = await host.TokenAsync(client.ClientId, client.ClientSecret, ct);
        var first = host.Keys.View.SigningKeyId;

        var id = await host.Keys.RotateSigningKeyAsync(ct);

        var after = await host.TokenAsync(client.ClientId, client.ClientSecret, ct);
        KeyIdOf(before).Should().Be(first);
        KeyIdOf(after).Should().Be(id).And.NotBe(first);
        (await host.HelloAsync(before, ct)).StatusCode.Should().Be(HttpStatusCode.OK, "the old key is accepted until its tokens expire");
        (await host.HelloAsync(after, ct)).StatusCode.Should().Be(HttpStatusCode.OK);
    }

    private async Task<ServerState> StartAsync()
    {
        var state = new ServerState(_store, Options.Create(new SkakelServerOptions { AppId = "test-app", AppVersion = "1", Port = 5240 }), _time, NullLogger<ServerState>.Instance);
        await state.StartAsync(TestContext.Current.CancellationToken);
        return state;
    }

    private static string? KeyIdOf(string token)
    {
        var header = token.Split('.')[0].Replace('-', '+').Replace('_', '/');
        header = header.PadRight(header.Length + ((4 - (header.Length % 4)) % 4), '=');
        return JsonDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(header))).RootElement.GetProperty("kid").GetString();
    }

    private static async Task EventuallyAsync(Func<bool> condition, CancellationToken ct)
    {
        var until = DateTime.UtcNow.AddSeconds(10);
        while (!condition())
        {
            if (DateTime.UtcNow > until)
            {
                throw new TimeoutException("The condition did not hold in 10 seconds.");
            }

            await Task.Delay(20, ct);
        }
    }
}
