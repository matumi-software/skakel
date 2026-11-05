using System.Net;
using System.Net.Http.Json;
using System.Net.WebSockets;
using System.Text;
using Skakel.Protocol;

namespace Skakel.Server.Tests;

/// <summary>Streams at /skakel/v1/streams/{type}: refusals before the upgrade, and the close codes when the server ends one.</summary>
public sealed class StreamTests : IAsyncLifetime
{
    private SkakelTestHost _host = null!;

    public async ValueTask InitializeAsync() => _host = await SkakelTestHost.StartAsync();

    public ValueTask DisposeAsync() => _host.DisposeAsync();

    [Fact]
    public async Task A_stream_without_a_token_is_refused_with_401_and_a_problem_a_person_can_read()
    {
        var ct = TestContext.Current.CancellationToken;
        using var https = _host.Https();

        using var response = await https.GetAsync("/skakel/v1/streams/echo?target=a", ct);
        var (socket, status) = await _host.OpenStreamAsync(null, "/skakel/v1/streams/echo?target=a", ct);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        response.Content.Headers.ContentType!.MediaType.Should().Be(SkakelProtocol.ProblemContentType);
        var problem = await response.Content.ReadFromJsonAsync<SkakelProblem>(SkakelJson.Options, ct);
        problem!.Status.Should().Be(401);
        problem.Detail.Should().NotBeNullOrWhiteSpace();
        socket.Should().BeNull();
        status.Should().Be(401);
    }

    [Fact]
    public async Task A_token_from_before_a_rotation_is_refused_with_401()
    {
        var ct = TestContext.Current.CancellationToken;
        var (client, token) = await _host.NewClientWithTokenAsync("bench-1", ct);
        await _host.Clients.RotateSecretAsync(client.ClientId, ct);

        var (_, status) = await _host.OpenStreamAsync(token, "/skakel/v1/streams/echo?target=a", ct);

        status.Should().Be(401);
    }

    [Fact]
    public async Task A_type_nobody_mapped_is_404_with_a_problem()
    {
        var ct = TestContext.Current.CancellationToken;
        var (_, token) = await _host.NewClientWithTokenAsync("bench-1", ct);
        using var https = _host.Https();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/skakel/v1/streams/usb?bus=1-1");
        request.Headers.Authorization = new("Bearer", token);

        using var response = await https.SendAsync(request, ct);
        var (_, status) = await _host.OpenStreamAsync(token, "/skakel/v1/streams/usb?bus=1-1", ct);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await response.Content.ReadFromJsonAsync<SkakelProblem>(SkakelJson.Options, ct))!.Detail.Should().Contain("usb");
        status.Should().Be(404);
    }

    [Theory]
    [InlineData("/skakel/v1/streams/echo", 422)]
    [InlineData("/skakel/v1/streams/echo?target=missing", 404)]
    [InlineData("/skakel/v1/streams/echo?target=busy", 409)]
    public async Task The_type_s_handler_refuses_before_the_upgrade(string path, int expected)
    {
        var ct = TestContext.Current.CancellationToken;
        var (_, token) = await _host.NewClientWithTokenAsync("bench-1", ct);

        var (socket, status) = await _host.OpenStreamAsync(token, path, ct);

        socket.Should().BeNull();
        status.Should().Be(expected);
    }

    [Fact]
    public async Task A_request_that_is_not_an_upgrade_is_400()
    {
        var ct = TestContext.Current.CancellationToken;
        var (_, token) = await _host.NewClientWithTokenAsync("bench-1", ct);
        using var https = _host.Https();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/skakel/v1/streams/echo?target=a");
        request.Headers.Authorization = new("Bearer", token);

        using var response = await https.SendAsync(request, ct);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task An_open_stream_carries_binary_and_text_frames_in_order()
    {
        var ct = TestContext.Current.CancellationToken;
        var (_, token) = await _host.NewClientWithTokenAsync("bench-1", ct);
        var (socket, _) = await _host.OpenStreamAsync(token, "/skakel/v1/streams/echo?target=a", ct);
        using var stream = socket!;

        await stream.SendAsync(new byte[] { 1, 2, 3 }, WebSocketMessageType.Binary, true, ct);
        await stream.SendAsync(Encoding.UTF8.GetBytes("""{"op":"ping"}"""), WebSocketMessageType.Text, true, ct);

        var buffer = new byte[64];
        var first = await stream.ReceiveAsync(buffer, ct);
        first.MessageType.Should().Be(WebSocketMessageType.Binary);
        buffer.AsSpan(0, first.Count).ToArray().Should().Equal(1, 2, 3);
        var second = await stream.ReceiveAsync(buffer, ct);
        second.MessageType.Should().Be(WebSocketMessageType.Text);
        Encoding.UTF8.GetString(buffer, 0, second.Count).Should().Be("""{"op":"ping"}""");

        await stream.CloseAsync(WebSocketCloseStatus.NormalClosure, null, ct);
        stream.CloseStatus.Should().Be(WebSocketCloseStatus.NormalClosure);
    }

    [Theory]
    [InlineData(false, SkakelCloseCodes.Revoked)]
    [InlineData(true, SkakelCloseCodes.Rotated)]
    public async Task A_revoke_or_rotation_closes_the_client_s_streams_with_its_code(bool rotate, int code)
    {
        var ct = TestContext.Current.CancellationToken;
        var (client, token) = await _host.NewClientWithTokenAsync("bench-1", ct);
        var (socket, _) = await _host.OpenStreamAsync(token, "/skakel/v1/streams/echo?target=a", ct);
        using var stream = socket!;

        if (rotate)
        {
            await _host.Clients.RotateSecretAsync(client.ClientId, ct);
        }
        else
        {
            await _host.Clients.RevokeAsync(client.ClientId, ct);
        }

        (await CloseCodeAsync(stream, ct)).Should().Be(code);
    }

    [Fact]
    public async Task Another_client_s_stream_survives_a_revoke()
    {
        var ct = TestContext.Current.CancellationToken;
        var (gone, _) = await _host.NewClientWithTokenAsync("gone", ct);
        var (_, token) = await _host.NewClientWithTokenAsync("stays", ct);
        var (socket, _) = await _host.OpenStreamAsync(token, "/skakel/v1/streams/echo?target=a", ct);
        using var stream = socket!;

        await _host.Clients.RevokeAsync(gone.ClientId, ct);

        await stream.SendAsync(new byte[] { 7 }, WebSocketMessageType.Binary, true, ct);
        var buffer = new byte[8];
        (await stream.ReceiveAsync(buffer, ct)).Count.Should().Be(1);
    }

    [Fact]
    public async Task Stopping_the_server_closes_streams_with_4003()
    {
        var ct = TestContext.Current.CancellationToken;
        var (_, token) = await _host.NewClientWithTokenAsync("bench-1", ct);
        var (socket, _) = await _host.OpenStreamAsync(token, "/skakel/v1/streams/echo?target=a", ct);
        using var stream = socket!;

        var stopping = _host.StopAsync();

        (await CloseCodeAsync(stream, ct)).Should().Be(SkakelCloseCodes.Stopping);
        await stopping;
    }

    [Fact]
    public async Task A_handler_closes_with_its_own_code_when_the_target_goes()
    {
        var ct = TestContext.Current.CancellationToken;
        var (_, token) = await _host.NewClientWithTokenAsync("bench-1", ct);
        var (socket, _) = await _host.OpenStreamAsync(token, "/skakel/v1/streams/echo?target=vanish", ct);
        using var stream = socket!;

        (await CloseCodeAsync(stream, ct)).Should().Be(SkakelCloseCodes.TargetGone);
        stream.CloseStatusDescription.Should().Be("unplugged");
    }

    /// <summary>Reads until the close frame and answers it; its code.</summary>
    private static async Task<int> CloseCodeAsync(WebSocket stream, CancellationToken ct)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limit.CancelAfter(TimeSpan.FromSeconds(10));
        var buffer = new byte[64];
        while ((await stream.ReceiveAsync(buffer, limit.Token)).MessageType != WebSocketMessageType.Close)
        {
            // Data still in flight.
        }

        if (stream.State == WebSocketState.CloseReceived)
        {
            await stream.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, null, limit.Token);
        }

        return (int)stream.CloseStatus!.Value;
    }
}
