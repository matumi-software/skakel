using System.Net.WebSockets;
using System.Text;
using Skakel.Protocol;
using Skakel.Protocol.Serial;

namespace Skakel.Client.Tests;

/// <summary>Streams against a real server: opening, refusals with their detail, close codes, and the serial type.</summary>
public sealed class StreamTests : IAsyncLifetime
{
    private SkakelHost _host = null!;

    public async ValueTask InitializeAsync() => _host = await SkakelHost.StartAsync();

    public ValueTask DisposeAsync() => _host.DisposeAsync();

    [Fact]
    public async Task OpenStreamAsync_opens_a_stream_that_carries_data_and_closes_normally()
    {
        var ct = TestContext.Current.CancellationToken;
        var (link, _) = await _host.LinkAsync();
        await using var __ = link;

        var opened = await link.OpenStreamAsync("echo", [new("target", "a b")], ct);

        opened.IsOpen.Should().BeTrue();
        var stream = opened.Stream!;
        await stream.WebSocket.SendAsync("ping"u8.ToArray(), WebSocketMessageType.Binary, true, ct);
        var buffer = new byte[16];
        var received = await stream.WebSocket.ReceiveAsync(buffer, ct);
        Encoding.ASCII.GetString(buffer, 0, received.Count).Should().Be("ping");
        stream.Close.Should().BeNull();

        await stream.CloseAsync(ct);

        stream.Close!.Reason.Should().Be(SkakelStreamCloseReason.Normal);
        stream.Dispose();
    }

    [Theory]
    [InlineData("echo", null, 422, SkakelStreamRefusalReason.InvalidQuery, "Say which target, as ?target=<name>.")]
    [InlineData("echo", "missing", 404, SkakelStreamRefusalReason.NotFound, "There is no target called missing.")]
    [InlineData("echo", "busy", 409, SkakelStreamRefusalReason.InUse, "bench-2 holds busy.")]
    [InlineData("nope", "a", 404, SkakelStreamRefusalReason.NotFound, "This server has no stream type 'nope'.")]
    public async Task OpenStreamAsync_returns_a_refusal_with_its_status_and_detail(string type, string? target, int status, SkakelStreamRefusalReason reason, string detail)
    {
        var (link, _) = await _host.LinkAsync();
        await using var __ = link;

        var opened = await link.OpenStreamAsync(type, target is null ? null : [new("target", target)], TestContext.Current.CancellationToken);

        opened.IsOpen.Should().BeFalse();
        opened.Refusal.Should().Be(new SkakelStreamRefusal(status, reason, detail));
    }

    [Fact]
    public async Task A_token_the_server_does_not_take_is_refused_with_401()
    {
        using var handler = Pinning.CreateHandler(() => _host.Pins);
        using var invoker = new HttpMessageInvoker(handler);

        var opened = await StreamOpener.OpenAsync(invoker, StreamOpener.Path(_host.Address, "echo", [new("target", "a")]), "echo", "not-a-token", TestContext.Current.CancellationToken);

        opened.Refusal!.Status.Should().Be(401);
        opened.Refusal.Reason.Should().Be(SkakelStreamRefusalReason.Unauthorized);
        opened.Refusal.Message.Should().StartWith("Open streams over HTTPS with a current token.");
    }

    [Fact]
    public async Task A_target_that_goes_away_closes_with_4004()
    {
        var ct = TestContext.Current.CancellationToken;
        var (link, _) = await _host.LinkAsync();
        await using var __ = link;
        await using var stream = (await link.OpenStreamAsync("echo", [new("target", "vanish")], ct)).Stream!;

        var received = await stream.WebSocket.ReceiveAsync(new byte[16], ct);

        received.MessageType.Should().Be(WebSocketMessageType.Close);
        stream.Close.Should().Be(new SkakelStreamClose(SkakelStreamCloseReason.TargetGone, 4004, "unplugged"));
    }

    [Fact]
    public async Task Revoking_the_client_closes_its_streams_with_4001()
    {
        var ct = TestContext.Current.CancellationToken;
        var (link, credentials) = await _host.LinkAsync();
        await using var __ = link;
        await using var stream = (await link.OpenStreamAsync("echo", [new("target", "a")], ct)).Stream!;

        await _host.Clients.RevokeAsync(credentials.ClientId, ct);

        (await stream.WebSocket.ReceiveAsync(new byte[16], ct)).MessageType.Should().Be(WebSocketMessageType.Close);
        stream.Close!.Reason.Should().Be(SkakelStreamCloseReason.Revoked);
        stream.Close.Message.Should().Be("The server revoked this client. Pair with the server again.");
    }

    [Fact]
    public void From_maps_close_codes_to_reasons()
    {
        SkakelStreamClose.From(1000, null).Reason.Should().Be(SkakelStreamCloseReason.Normal);
        SkakelStreamClose.From(4002, null).Reason.Should().Be(SkakelStreamCloseReason.Rotated);
        SkakelStreamClose.From(4003, null).Reason.Should().Be(SkakelStreamCloseReason.ServerStopping);
        SkakelStreamClose.From(4100, null).Reason.Should().Be(SkakelStreamCloseReason.TypeDefined);
        SkakelStreamClose.From(4999, null).Reason.Should().Be(SkakelStreamCloseReason.TypeDefined);
        SkakelStreamClose.From(null, null).Reason.Should().Be(SkakelStreamCloseReason.ConnectionLost);
        SkakelStreamClose.From(3000, null).Reason.Should().Be(SkakelStreamCloseReason.Other);
    }

    [Fact]
    public async Task OpenSerialAsync_starts_with_the_port_as_it_is()
    {
        var (link, _) = await _host.LinkAsync();
        await using var __ = link;

        await using var serial = (await link.OpenSerialAsync("COM1", TestContext.Current.CancellationToken)).Stream!;

        serial.LineSettings.Should().Be(new SerialLineSettings(9600, 8, SerialParity.None, SerialStopBits.One, SerialFlowControl.None));
        serial.ModemStatus.Should().Be(new SerialModemStatus(true, false, false, false));
    }

    [Fact]
    public async Task SetLineSettingsAsync_is_done_when_the_server_echoes_it()
    {
        var (link, _) = await _host.LinkAsync();
        await using var __ = link;
        await using var serial = (await link.OpenSerialAsync("COM1", TestContext.Current.CancellationToken)).Stream!;
        var wanted = new SerialLineSettings(115200, 7, SerialParity.Even, SerialStopBits.Two, SerialFlowControl.RtsCts);

        var change = await serial.SetLineSettingsAsync(wanted, TestContext.Current.CancellationToken);

        change.Should().Be(new SkakelSerialChange(true, wanted, null));
        serial.LineSettings.Should().Be(wanted);
    }

    [Fact]
    public async Task SetLineSettingsAsync_reports_a_change_the_port_refused()
    {
        var (link, _) = await _host.LinkAsync();
        await using var __ = link;
        await using var serial = (await link.OpenSerialAsync("COM1", TestContext.Current.CancellationToken)).Stream!;
        var before = serial.LineSettings;

        var change = await serial.SetLineSettingsAsync(before with { Baud = PretendSerial.UnsupportedBaud }, TestContext.Current.CancellationToken);

        change.Should().Be(new SkakelSerialChange(false, before, "This port cannot run at 12345 baud."));
    }

    [Fact]
    public async Task SendAsync_and_ReceiveAsync_carry_the_bytes_and_control_messages_between_them()
    {
        var ct = TestContext.Current.CancellationToken;
        var (link, _) = await _host.LinkAsync();
        await using var __ = link;
        await using var serial = (await link.OpenSerialAsync("COM1", ct)).Stream!;
        var lines = new Recorder<SerialModemStatus>();
        serial.ModemStatusChanged += lines.Record;

        await serial.SendAsync("AT\r"u8.ToArray(), ct);
        await serial.SetModemLinesAsync(dtr: true, cancellationToken: ct);
        await serial.SendAsync("OK\r"u8.ToArray(), ct);

        var buffer = new byte[64];
        var read = 0;
        while (read < 6)
        {
            read += await serial.ReceiveAsync(buffer.AsMemory(read), ct);
        }

        Encoding.ASCII.GetString(buffer, 0, read).Should().Be("AT\rOK\r");
        (await lines.WaitAsync(_ => true)).Should().Be(new SerialModemStatus(true, true, true, false));
        serial.ModemStatus.Dsr.Should().BeTrue();
    }

    [Fact]
    public async Task OpenSerialAsync_refuses_a_port_in_use()
    {
        var (link, _) = await _host.LinkAsync();
        await using var __ = link;

        var opened = await link.OpenSerialAsync("busy", TestContext.Current.CancellationToken);

        opened.Refusal.Should().Be(new SkakelStreamRefusal(409, SkakelStreamRefusalReason.InUse, "bench-2 holds busy."));
    }

    [Fact]
    public async Task A_port_fault_ends_the_stream_with_4100()
    {
        var (link, _) = await _host.LinkAsync();
        await using var __ = link;
        await using var serial = (await link.OpenSerialAsync("fault", TestContext.Current.CancellationToken)).Stream!;

        var closed = await serial.Closed.WaitAsync(TimeSpan.FromSeconds(15), TestContext.Current.CancellationToken);

        closed.Code.Should().Be(SerialStreamType.PortFault);
        closed.Reason.Should().Be(SkakelStreamCloseReason.TypeDefined);
        (await serial.ReceiveAsync(new byte[8], TestContext.Current.CancellationToken)).Should().Be(0);
    }
}
