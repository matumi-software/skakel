using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Skakel.Protocol;

namespace Skakel.Server.Tests;

/// <summary>The app's hub on SkakelHub: certificates on connect, and SkakelClosing before a revoke, rotation or stop ends it.</summary>
public sealed class HubTests : IAsyncLifetime
{
    private SkakelTestHost _host = null!;

    public async ValueTask InitializeAsync() => _host = await SkakelTestHost.StartAsync();

    public ValueTask DisposeAsync() => _host.DisposeAsync();

    [Fact]
    public async Task OnConnectedAsync_sends_the_certificates_and_the_app_s_own_messages_work()
    {
        var ct = TestContext.Current.CancellationToken;
        var (client, token) = await _host.NewClientWithTokenAsync("bench-1", ct);
        var hub = await _host.ConnectHubAsync(token, ct);
        await using var connection = hub.Connection;
        var greeted = new TaskCompletionSource<string>();
        connection.On<string>("Greeted", text => greeted.TrySetResult(text));

        var certificates = await hub.CertificatesAsync(_ => true, ct);
        await connection.InvokeAsync("Greet", "hi", ct);

        certificates.GetProperty("fingerprint").GetString().Should().Be(_host.Keys.Fingerprint);
        certificates.GetProperty("nextFingerprint").ValueKind.Should().Be(JsonValueKind.Null);
        (await greeted.Task.WaitAsync(TimeSpan.FromSeconds(10), ct)).Should().Be($"{client.ClientId}: hi");
    }

    [Theory]
    [InlineData(false, SkakelClosingReasons.Revoked)]
    [InlineData(true, SkakelClosingReasons.Rotated)]
    public async Task A_revoke_or_rotation_sends_SkakelClosing_and_ends_the_connection(bool rotate, string reason)
    {
        var ct = TestContext.Current.CancellationToken;
        var (client, token) = await _host.NewClientWithTokenAsync("bench-1", ct);
        var hub = await _host.ConnectHubAsync(token, ct);
        await using var connection = hub.Connection;
        await hub.CertificatesAsync(_ => true, ct);

        if (rotate)
        {
            await _host.Clients.RotateSecretAsync(client.ClientId, ct);
        }
        else
        {
            await _host.Clients.RevokeAsync(client.ClientId, ct);
        }

        (await hub.Closing.WaitAsync(TimeSpan.FromSeconds(10), ct)).Should().Be(reason);
        await hub.Closed.WaitAsync(TimeSpan.FromSeconds(10), ct);
    }

    [Fact]
    public async Task Another_client_s_connection_survives_a_revoke()
    {
        var ct = TestContext.Current.CancellationToken;
        var (gone, goneToken) = await _host.NewClientWithTokenAsync("gone", ct);
        var (_, stayToken) = await _host.NewClientWithTokenAsync("stays", ct);
        var goneHub = await _host.ConnectHubAsync(goneToken, ct);
        await using var goneConnection = goneHub.Connection;
        var stayHub = await _host.ConnectHubAsync(stayToken, ct);
        await using var stayConnection = stayHub.Connection;

        await _host.Clients.RevokeAsync(gone.ClientId, ct);
        await goneHub.Closed.WaitAsync(TimeSpan.FromSeconds(10), ct);

        stayConnection.State.Should().Be(HubConnectionState.Connected);
        await stayConnection.InvokeAsync("Greet", "still here", ct);
    }

    [Fact]
    public async Task A_token_from_before_a_rotation_cannot_connect()
    {
        var ct = TestContext.Current.CancellationToken;
        var (client, token) = await _host.NewClientWithTokenAsync("bench-1", ct);
        await _host.Clients.RotateSecretAsync(client.ClientId, ct);

        var connect = () => _host.ConnectHubAsync(token, ct);

        await connect.Should().ThrowAsync<HttpRequestException>();
    }

    [Fact]
    public async Task Stopping_the_server_sends_SkakelClosing_stopping()
    {
        var ct = TestContext.Current.CancellationToken;
        var (_, token) = await _host.NewClientWithTokenAsync("bench-1", ct);
        var hub = await _host.ConnectHubAsync(token, ct);
        await using var connection = hub.Connection;
        await hub.CertificatesAsync(_ => true, ct);

        await _host.StopAsync();

        (await hub.Closing.WaitAsync(TimeSpan.FromSeconds(10), ct)).Should().Be(SkakelClosingReasons.Stopping);
    }

    [Fact]
    public async Task MapSkakelHub_refuses_message_names_that_start_with_Skakel_and_Skakel_s_own_paths()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton<ISkakelStore>(new InMemorySkakelStore());
        builder.Services.AddSkakelServer(o =>
        {
            o.AppId = "test-app";
            o.AppVersion = "1";
            o.Port = 5240;
        });
        await using var app = builder.Build();

        FluentActions.Invoking(() => app.MapSkakelHub<RudeHub>("rude")).Should().Throw<ArgumentException>().WithMessage("*SkakelPing*");
        FluentActions.Invoking(() => app.MapSkakelHub<RudeClientHub>("rude")).Should().Throw<ArgumentException>().WithMessage("*SkakelPush*");
        FluentActions.Invoking(() => app.MapSkakelHub<TestHub>("streams")).Should().Throw<ArgumentException>();
    }

    public interface IRudeClient
    {
        Task SkakelPush();
    }

    public sealed class RudeHub : SkakelHub<ITestClient>
    {
        public Task SkakelPing() => Clients.Caller.Greeted("pong");
    }

    public sealed class RudeClientHub : SkakelHub<IRudeClient>;
}
