using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Text;
using Skakel.Client;
using Skakel.Client.Interop;
using Skakel.Protocol;
using Skakel.Protocol.Serial;
using static Skakel.Client.Interop.Script;

// One scenario per run, against a Rust server the Rust test started on loopback:
//
//   Skakel.Client.Interop <scenario> <tcp port> <fingerprint> [more arguments]
//
// Scenarios that need credentials take `<client id> <secret>` after the fingerprint; `discover` takes the
// UDP port. The server is the Rust test's test app: name "rust-bench", app "test-app" 1.2.3, a hub at
// `hub` with Greet, Echo and Connection, a stream type `echo` and a pretend `serial` port. See
// Script.cs for what is printed. The exit code is 0 when every check held.
if (args.Length < 3 || !int.TryParse(args[1], out var port))
{
    Console.Error.WriteLine("Usage: Skakel.Client.Interop <scenario> <tcp port> <fingerprint> [arguments]");
    return 2;
}

var address = new Uri($"https://127.0.0.1:{port}/");
var fingerprint = args[2];
var pins = new SkakelPins(fingerprint);
var credentials = args.Length >= 5 ? new SkakelCredentials(args[3], args[4]) : null;
try
{
    using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(2));
    await Task.Run(() => Run(args[0], address, pins, credentials, args.Length > 3 ? args[3] : "", timeout.Token), timeout.Token);
    Say("PASSED");
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"FAIL {ex.GetType().Name}: {ex.Message}");
    return 1;
}

static SkakelCredentials Need(SkakelCredentials? credentials) =>
    credentials ?? throw new ArgumentException("This scenario takes a client id and a secret after the fingerprint.");

static Task Run(string scenario, Uri address, SkakelPins pins, SkakelCredentials? credentials, string extra, CancellationToken ct) => scenario switch
{
    "info" => Scenarios.InfoAsync(address, pins, ct),
    "discover" => Scenarios.DiscoverAsync(int.Parse(extra, System.Globalization.CultureInfo.InvariantCulture), pins, ct),
    "pair" => Scenarios.PairAsync(address, pins, ct),
    "credentials" => Scenarios.CredentialsAsync(address, pins, Need(credentials), ct),
    "link" => Scenarios.LinkAsync(address, pins, Need(credentials), ct),
    "handover" => Scenarios.HandoverAsync(address, pins, Need(credentials), cancel: false, ct),
    "handover-cancel" => Scenarios.HandoverAsync(address, pins, Need(credentials), cancel: true, ct),
    "revoked" => Scenarios.EndedAsync(address, pins, Need(credentials), "revoke", SkakelFailureKind.Revoked, SkakelStreamCloseReason.Revoked, ct),
    "rotated" => Scenarios.EndedAsync(address, pins, Need(credentials), "rotate", SkakelFailureKind.Rotated, SkakelStreamCloseReason.Rotated, ct),
    "stopping" => Scenarios.EndedAsync(address, pins, Need(credentials), "stop", SkakelFailureKind.ServerStopping, SkakelStreamCloseReason.ServerStopping, ct),
    "streams" => Scenarios.StreamsAsync(address, pins, Need(credentials), ct),
    "serial" => Scenarios.SerialAsync(address, pins, Need(credentials), ct),
    _ => throw new ArgumentException($"No scenario '{scenario}'."),
};

internal static class Scenarios
{
    public static async Task InfoAsync(Uri address, SkakelPins pins, CancellationToken ct)
    {
        var info = await SkakelInfoClient.ReadAsync(address, pins, cancellationToken: ct);
        Check(info.Name == "rust-bench", "info: the server's name");
        Check(info.App == new SkakelApp("test-app", "1.2.3"), "info: the app");
        Check(info.Versions.SequenceEqual([1]), "info: the versions");

        var other = new SkakelPins(string.Join(':', Enumerable.Repeat("0F", 32)));
        await Fails(() => SkakelInfoClient.ReadAsync(address, other, cancellationToken: ct), SkakelFailureKind.CertificateMismatch, "info: another pin");
    }

    public static async Task DiscoverAsync(int udpPort, SkakelPins pins, CancellationToken ct)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        await socket.SendToAsync(SkakelDiscovery.CreateProbe(), SocketFlags.None, new IPEndPoint(IPAddress.Loopback, udpPort), ct);
        var buffer = new byte[2048];
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limit.CancelAfter(TimeSpan.FromSeconds(5));
        var received = await socket.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), limit.Token);
        Check(SkakelDiscovery.TryParseAnswer(buffer.AsSpan(0, received.ReceivedBytes), out var answer), "discover: the answer parses");
        Check(answer.Name == "rust-bench" && answer.App == new SkakelApp("test-app", "1.2.3"), "discover: name and app");
        Check(answer.Versions.SequenceEqual([1]), "discover: versions");
        Check(pins.Trusts(answer.Fingerprint), "discover: the fingerprint is the server's certificate");
        Say($"OK discover: port {answer.Port}");
        Say($"PORT {answer.Port}");

        // A short datagram is no probe: nothing comes back.
        await socket.SendToAsync(new byte[100], SocketFlags.None, new IPEndPoint(IPAddress.Loopback, udpPort), ct);
        limit.CancelAfter(TimeSpan.FromMilliseconds(700));
        try
        {
            await socket.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), limit.Token);
            Check(false, "discover: a short datagram is not answered");
        }
        catch (OperationCanceledException)
        {
            Check(true, "discover: a short datagram is not answered");
        }
    }

    public static async Task PairAsync(Uri address, SkakelPins pins, CancellationToken ct)
    {
        await using (var pairing = await SkakelPairingClient.OpenAsync(address, pins.Fingerprint, "interop client", cancellationToken: ct))
        {
            Check(pairing.ServerName == "rust-bench", "pair: the server's name");
            Say($"CODE {pairing.Code}");
            Wait("approve");
            var credentials = await pairing.WaitAsync(ct);
            Say($"CREDENTIALS {credentials.ClientId} {credentials.ClientSecret}");
            await using var link = new SkakelLink(address, pins, credentials, StderrLoggerProvider.Options());
            var hello = await link.HelloAsync(ct);
            Check(hello.ClientId == credentials.ClientId && hello.Server == "rust-bench", "pair: the new credentials sign in");
        }

        // Refused on the server.
        await using (var pairing = await SkakelPairingClient.OpenAsync(address, pins.Fingerprint, "refused client", cancellationToken: ct))
        {
            Say($"CODE {pairing.Code}");
            Wait("deny");
            await Fails(() => pairing.WaitAsync(ct), SkakelFailureKind.PairingDenied, "pair: refused on the server");
        }

        // The code typed wrong three times.
        await using (var pairing = await SkakelPairingClient.OpenAsync(address, pins.Fingerprint, "wrong code client", cancellationToken: ct))
        {
            Say($"CODE {pairing.Code}");
            Wait("wrong-codes");
            await Fails(() => pairing.WaitAsync(ct), SkakelFailureKind.PairingDenied, "pair: three wrong codes");
        }

        // Withdrawn by the client.
        await using (var pairing = await SkakelPairingClient.OpenAsync(address, pins.Fingerprint, "withdrawn client", cancellationToken: ct))
        {
            Say($"CODE {pairing.Code}");
            Wait("seen");
            await pairing.WithdrawAsync();
            Say("OK pair: withdrawn");
            Wait("gone");
        }
    }

    public static async Task CredentialsAsync(Uri address, SkakelPins pins, SkakelCredentials credentials, CancellationToken ct)
    {
        var wrong = credentials with { ClientSecret = "not-the-secret" };
        for (var attempt = 1; attempt <= 10; attempt++)
        {
            await using var link = new SkakelLink(address, pins, wrong);
            await Fails(() => link.HelloAsync(ct), SkakelFailureKind.RejectedCredentials, $"credentials: wrong secret {attempt}");
        }

        await using (var link = new SkakelLink(address, pins, wrong))
        {
            await Fails(() => link.HelloAsync(ct), SkakelFailureKind.TooManyRequests, "credentials: the eleventh wrong secret");
        }

        await using (var link = new SkakelLink(address, pins, credentials, StderrLoggerProvider.Options()))
        {
            await Fails(() => link.HelloAsync(ct), SkakelFailureKind.TooManyRequests, "credentials: the right secret too, until the minute is up");
        }
    }

    public static async Task LinkAsync(Uri address, SkakelPins pins, SkakelCredentials credentials, CancellationToken ct)
    {
        await using var link = new SkakelLink(address, pins, credentials, StderrLoggerProvider.Options());
        var statuses = new Recorder<SkakelLinkStatus>();
        link.StatusChanged += statuses.Record;
        var greetings = new Recorder<string>();
        using var handler = link.On<string>("Greeted", greetings.Record);
        link.Start();
        await statuses.WaitAsync(s => s.State == SkakelLinkState.Connected);
        Check(true, "link: the hub connects");

        var hello = await link.HelloAsync(ct);
        Check(hello.ClientId == credentials.ClientId && hello.Server == "rust-bench", "link: hello");
        Check(await link.InvokeAsync<string>("Echo", ["echo"], ct) == "echo", "link: Echo answers");
        await link.InvokeAsync("Greet", ["hello"], ct);
        Check(await greetings.WaitAsync(_ => true) == $"{credentials.ClientId}: hello", "link: the server's message arrives");
        var connection = await link.InvokeAsync<string>("Connection", cancellationToken: ct);
        Check(connection.Length > 0, "link: a result of text");

        var failure = await Record(() => link.InvokeAsync("NoSuchMethod", cancellationToken: ct));
        Check(failure is not null, "link: an unknown method is an error");
        Check((await link.InvokeAsync<string>("Echo", ["still here"], ct)) == "still here", "link: the connection survives it");
        await link.SendAsync("Greet", ["sent"], ct);
        Check(await greetings.WaitAsync(m => m.EndsWith("sent", StringComparison.Ordinal)) == $"{credentials.ClientId}: sent", "link: a call that wants no answer");

        // A second link of the same client, and the first one's token reused for the hello.
        await using var second = new SkakelLink(address, pins, credentials, StderrLoggerProvider.Options());
        Check((await second.HelloAsync(ct)).ClientId == credentials.ClientId, "link: a second link signs in");
        Check((await link.GetAccessTokenAsync(ct)).Length > 0, "link: a token");

        await link.StopAsync();
        Check(link.Status.State == SkakelLinkState.Stopped, "link: stopped");
        var again = new Recorder<SkakelLinkStatus>();
        link.StatusChanged += again.Record;
        link.Start();
        await again.WaitAsync(s => s.State == SkakelLinkState.Connected);
        Check(true, "link: connects again after a stop");
    }

    public static async Task HandoverAsync(Uri address, SkakelPins pins, SkakelCredentials credentials, bool cancel, CancellationToken ct)
    {
        await using var link = new SkakelLink(address, pins, credentials, StderrLoggerProvider.Options());
        var pinsSeen = new Recorder<SkakelPins>();
        link.PinsChanged += pinsSeen.Record;
        var statuses = new Recorder<SkakelLinkStatus>();
        link.StatusChanged += statuses.Record;
        link.Start();
        await statuses.WaitAsync(s => s.State == SkakelLinkState.Connected);
        var current = pins.Fingerprint;

        Wait("prepare");
        var withNext = await pinsSeen.WaitAsync(p => p.NextFingerprint is not null);
        var next = withNext.NextFingerprint!;
        Check(Fingerprints.AreEqual(withNext.Fingerprint, current), "handover: the client learns the next certificate and keeps the current one");
        Wait("acknowledged");
        Check(true, "handover: the server heard the client has it");

        if (cancel)
        {
            Wait("cancel");
            await pinsSeen.WaitAsync(p => p.NextFingerprint is null);
            Check(Fingerprints.AreEqual(link.Pins.Fingerprint, current) && link.Pins.NextFingerprint is null, "handover: a cancelled handover is forgotten");
            return;
        }

        Wait("switch");
        await pinsSeen.WaitAsync(p => p.NextFingerprint is null && Fingerprints.AreEqual(p.Fingerprint, next));
        Check(link.Pins == new SkakelPins(next), "handover: the client's pin is the new certificate");

        await using var learned = new SkakelLink(address, link.Pins, credentials);
        Check((await learned.HelloAsync(ct)).ClientId == credentials.ClientId, "handover: the learned pins reach the new certificate");
        await using var stale = new SkakelLink(address, new SkakelPins(current), credentials);
        await Fails(() => stale.HelloAsync(ct), SkakelFailureKind.CertificateMismatch, "handover: the old pin alone does not");

        await link.StopAsync();
        var again = new Recorder<SkakelLinkStatus>();
        link.StatusChanged += again.Record;
        link.Start();
        await again.WaitAsync(s => s.State == SkakelLinkState.Connected);
        Check(true, "handover: the link connects again across the switch");
    }

    /// <summary>A link and two streams are open, the server does <paramref name="action"/>, and all three end the way the protocol says.</summary>
    public static async Task EndedAsync(Uri address, SkakelPins pins, SkakelCredentials credentials, string action, SkakelFailureKind failure, SkakelStreamCloseReason closeReason, CancellationToken ct)
    {
        await using var link = new SkakelLink(address, pins, credentials, StderrLoggerProvider.Options());
        var statuses = new Recorder<SkakelLinkStatus>();
        link.StatusChanged += statuses.Record;
        link.Start();
        await statuses.WaitAsync(s => s.State == SkakelLinkState.Connected);
        await using var echo = (await link.OpenStreamAsync("echo", [new("target", "a")], ct)).Stream!;
        await using var serial = (await link.OpenSerialAsync("COM1", ct)).Stream!;

        Wait(action);

        var ended = await statuses.WaitAsync(s => s.State is SkakelLinkState.Closed or SkakelLinkState.Failed && s.Failure?.Kind == failure);
        Check(ended.Failure!.Kind == failure, $"{action}: the link says {failure}");
        var received = await echo.WebSocket.ReceiveAsync(new byte[16], ct);
        Check(received.MessageType == WebSocketMessageType.Close && echo.Close?.Reason == closeReason, $"{action}: the echo stream closes with {closeReason} (got {echo.Close?.Reason})");
        var closed = await serial.Closed.WaitAsync(TimeSpan.FromSeconds(15), ct);
        Check(closed.Reason == closeReason, $"{action}: the serial stream closes with {closeReason}");
        Say($"CLOSE {echo.Close?.Code}");

        if (action == "stop")
        {
            return;
        }

        // The credentials no longer work: a new link is refused.
        await using var fresh = new SkakelLink(address, pins, credentials, StderrLoggerProvider.Options());
        await Fails(() => fresh.HelloAsync(ct), SkakelFailureKind.RejectedCredentials, $"{action}: the old credentials are refused");
    }

    public static async Task StreamsAsync(Uri address, SkakelPins pins, SkakelCredentials credentials, CancellationToken ct)
    {
        await using var link = new SkakelLink(address, pins, credentials, StderrLoggerProvider.Options());

        var opened = await link.OpenStreamAsync("echo", [new("target", "a b")], ct);
        Check(opened.IsOpen, "streams: an echo stream opens");
        var stream = opened.Stream!;
        await stream.WebSocket.SendAsync("ping"u8.ToArray(), WebSocketMessageType.Binary, true, ct);
        var buffer = new byte[16];
        var received = await stream.WebSocket.ReceiveAsync(buffer, ct);
        Check(received.MessageType == WebSocketMessageType.Binary && Encoding.ASCII.GetString(buffer, 0, received.Count) == "ping", "streams: a binary frame comes back");
        await stream.WebSocket.SendAsync("{\"op\":\"x\"}"u8.ToArray(), WebSocketMessageType.Text, true, ct);
        received = await stream.WebSocket.ReceiveAsync(buffer, ct);
        Check(received.MessageType == WebSocketMessageType.Text && Encoding.ASCII.GetString(buffer, 0, received.Count) == "{\"op\":\"x\"}", "streams: a text frame comes back as text");
        var big = new byte[200_000];
        new Random(7).NextBytes(big);
        var echoed = new List<byte>();
        var send = Task.Run(async () =>
        {
            for (var offset = 0; offset < big.Length; offset += 20_000)
            {
                await stream.WebSocket.SendAsync(big.AsMemory(offset, 20_000), WebSocketMessageType.Binary, true, ct);
            }
        }, ct);
        var chunk = new byte[64 * 1024];
        while (echoed.Count < big.Length)
        {
            var part = await stream.WebSocket.ReceiveAsync(chunk, ct);
            echoed.AddRange(chunk.AsSpan(0, part.Count).ToArray());
        }

        await send;
        Check(echoed.SequenceEqual(big), "streams: 200000 bytes come back in order");
        Check(stream.Close is null, "streams: still open");
        await stream.CloseAsync(ct);
        Check(stream.Close?.Reason == SkakelStreamCloseReason.Normal, "streams: the client closes normally");
        stream.Dispose();

        await Refused(link, "echo", null, 422, SkakelStreamRefusalReason.InvalidQuery, "Say which target, as ?target=<name>.", ct);
        await Refused(link, "echo", "missing", 404, SkakelStreamRefusalReason.NotFound, "There is no target called missing.", ct);
        await Refused(link, "echo", "busy", 409, SkakelStreamRefusalReason.InUse, "bench-2 holds busy.", ct);
        await Refused(link, "nope", "a", 404, SkakelStreamRefusalReason.NotFound, "This server has no stream type 'nope'.", ct);

        await using var vanish = (await link.OpenStreamAsync("echo", [new("target", "vanish")], ct)).Stream!;
        var gone = await vanish.WebSocket.ReceiveAsync(new byte[16], ct);
        Check(gone.MessageType == WebSocketMessageType.Close && vanish.Close == new SkakelStreamClose(SkakelStreamCloseReason.TargetGone, 4004, "unplugged"), "streams: a target that goes away closes with 4004");

        // A stream refused for a token the server does not take.
        var bad = new SkakelLink(address, pins, credentials with { ClientSecret = "wrong" });
        await using (bad)
        {
            await Fails(() => bad.OpenStreamAsync("echo", [new("target", "a")], ct), SkakelFailureKind.RejectedCredentials, "streams: wrong credentials");
        }
    }

    public static async Task SerialAsync(Uri address, SkakelPins pins, SkakelCredentials credentials, CancellationToken ct)
    {
        await using var link = new SkakelLink(address, pins, credentials, StderrLoggerProvider.Options());
        await using var serial = (await link.OpenSerialAsync("COM1", ct)).Stream!;
        Check(serial.LineSettings == new SerialLineSettings(9600, 8, SerialParity.None, SerialStopBits.One, SerialFlowControl.None), "serial: the port as it is");
        Check(serial.ModemStatus == new SerialModemStatus(true, false, false, false), "serial: the modem lines as they are");

        var wanted = new SerialLineSettings(115200, 7, SerialParity.Even, SerialStopBits.Two, SerialFlowControl.RtsCts);
        var change = await serial.SetLineSettingsAsync(wanted, ct);
        Check(change == new SkakelSerialChange(true, wanted, null) && serial.LineSettings == wanted, "serial: a change is done when the server echoes it");
        var before = serial.LineSettings;
        var refused = await serial.SetLineSettingsAsync(before with { Baud = 12345 }, ct);
        Check(refused == new SkakelSerialChange(false, before, "This port cannot run at 12345 baud."), "serial: a change the port refused");

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

        Check(Encoding.ASCII.GetString(buffer, 0, read) == "AT\rOK\r", "serial: bytes and control messages keep their order");
        Check(await lines.WaitAsync(_ => true) == new SerialModemStatus(true, true, true, false), "serial: the modem status arrives");

        var busy = await link.OpenSerialAsync("busy", ct);
        Check(busy.Refusal == new SkakelStreamRefusal(409, SkakelStreamRefusalReason.InUse, "bench-2 holds busy."), "serial: a port in use is refused with 409");
        var fault = (await link.OpenSerialAsync("fault", ct)).Stream!;
        await using (fault)
        {
            var closed = await fault.Closed.WaitAsync(TimeSpan.FromSeconds(15), ct);
            Check(closed.Code == SerialStreamType.PortFault && closed.Reason == SkakelStreamCloseReason.TypeDefined, "serial: a port fault ends the stream with 4100");
        }
    }

    private static async Task Refused(SkakelLink link, string type, string? target, int status, SkakelStreamRefusalReason reason, string detail, CancellationToken ct)
    {
        var opened = await link.OpenStreamAsync(type, target is null ? null : [new("target", target)], ct);
        Check(opened.Refusal == new SkakelStreamRefusal(status, reason, detail), $"streams: {type} {target ?? "(no target)"} is refused with {status} and its words");
    }

    private static async Task<Exception?> Record(Func<Task> call)
    {
        try
        {
            await call();
            return null;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }
}
