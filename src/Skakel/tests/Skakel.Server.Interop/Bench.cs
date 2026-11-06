using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Skakel.Protocol;
using Skakel.Protocol.Serial;
using Skakel.Server;

namespace Skakel.Server.Interop;

/// <summary>The messages the test hub sends its clients.</summary>
public interface ITestClient
{
    Task Greeted(string text);
}

/// <summary>An app's hub, as small as one gets.</summary>
public sealed class TestHub : SkakelHub<ITestClient>
{
    public Task Greet(string text) => Clients.Caller.Greeted($"{SkakelClientId}: {text}");

#pragma warning disable CA1822 // SignalR calls instance methods only.
    public string Echo(string text) => text;
#pragma warning restore CA1822

    public string Connection() => Context.ConnectionId;

    /// <summary>
    /// Tells the caller the server presents <paramref name="fingerprint"/>, true or not.
    /// Sent past the typed client, which may not name Skakel's own messages.
    /// </summary>
    public Task Claim(string fingerprint, string? next) =>
        Context.GetHttpContext()!.RequestServices.GetRequiredService<HubLifetimeManager<TestHub>>()
            .SendConnectionAsync(Context.ConnectionId, SkakelHubMethods.Certificates, [new SkakelCertificates(fingerprint, next)]);
}

/// <summary>
/// A real Skakel server: Kestrel on loopback with the server's own self-signed certificate, wired the
/// way an app wires it, with a hub at <c>/skakel/v1/hub</c>, a test stream type <c>echo</c> and a
/// pretend <c>serial</c> port. The same as the .NET client's tests talk to.
/// </summary>
internal sealed class Bench : IAsyncDisposable
{
    private readonly WebApplication _app;
    private int _negotiates;
    private int _tokens;

    private Bench(WebApplication app, int port)
    {
        _app = app;
        Port = port;
    }

    public int Port { get; }

    public SkakelClients Clients => _app.Services.GetRequiredService<SkakelClients>();

    public SkakelKeys Keys => _app.Services.GetRequiredService<SkakelKeys>();

    public Skakel.Server.SkakelPairing Pairing => _app.Services.GetRequiredService<Skakel.Server.SkakelPairing>();

    public SkakelSessions Sessions => _app.Services.GetRequiredService<SkakelSessions>();

    /// <summary>When set, <c>/skakel/info</c> lists these versions instead, as a server of another version would.</summary>
    public IReadOnlyList<int>? InfoVersions { get; set; }

    public int Negotiates => Volatile.Read(ref _negotiates);

    public int Tokens => Volatile.Read(ref _tokens);

    public static async Task<Bench> StartAsync(InMemorySkakelStore store, int? port, int? discoveryPort)
    {
        var tcp = port ?? FreeTcp();
        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(IPAddress.Loopback, tcp, listen =>
            listen.UseHttps(https => https.UseSkakelCertificate(kestrel.ApplicationServices))));
        builder.Services.AddSingleton<ISkakelStore>(store);
        builder.Services.AddSkakelServer(o =>
        {
            o.AppId = "test-app";
            o.AppVersion = "1.2.3";
            o.Name = "bench";
            o.Port = tcp;
            o.DiscoveryEnabled = discoveryPort is not null;
            o.DiscoveryPort = discoveryPort;
        });

        var app = builder.Build();
        Bench? bench = null;
        app.Use(async (http, next) =>
        {
            if (bench?.InfoVersions is { } versions && http.Request.Path == SkakelProtocol.InfoPath)
            {
                await http.Response.WriteAsJsonAsync(new SkakelInfo("bench", new SkakelApp("test-app", "9.0.0"), versions), SkakelJson.Options);
                return;
            }

            if (bench is not null && http.Request.Path.StartsWithSegments("/skakel/v1/hub/negotiate"))
            {
                Interlocked.Increment(ref bench._negotiates);
            }

            if (bench is not null && http.Request.Path == SkakelProtocol.TokenPath)
            {
                Interlocked.Increment(ref bench._tokens);
            }

            await next(http);
        });
        app.UseWebSockets();
        app.MapSkakel();
        app.MapSkakelHub<TestHub>("hub");
        app.MapSkakelStream("echo", EchoStream.OpenAsync);
        app.MapSkakelStream(SerialStreamType.Type, PretendSerial.OpenAsync);
        // A stream type whose server never answers the upgrade.
        app.MapGet($"{SkakelProtocol.StreamsPath}/stall", (HttpContext http) => Task.Delay(Timeout.Infinite, http.RequestAborted));
        await app.StartAsync();
        bench = new Bench(app, tcp);
        return bench;
    }

    public async ValueTask DisposeAsync() => await _app.DisposeAsync();

    private static int FreeTcp()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }
}

/// <summary>
/// The test stream type. The query names a target: none is 422, <c>missing</c> 404, <c>busy</c> 409,
/// <c>vanish</c> opens and closes at once with 4004, anything else echoes what it receives.
/// </summary>
internal static class EchoStream
{
    public static ValueTask<SkakelStreamResult> OpenAsync(SkakelStreamRequest request)
    {
        var target = request.Query["target"].ToString();
        return ValueTask.FromResult(target switch
        {
            "" => SkakelStreamResult.Invalid("Say which target, as ?target=<name>."),
            "missing" => SkakelStreamResult.NotFound("There is no target called missing."),
            "busy" => SkakelStreamResult.InUse("bench-2 holds busy."),
            "vanish" => SkakelStreamResult.Accept(session => session.CloseAsync(SkakelCloseCodes.TargetGone, "unplugged")),
            _ => SkakelStreamResult.Accept(EchoAsync),
        });
    }

    private static async Task EchoAsync(SkakelStreamSession session)
    {
        var buffer = new byte[4096];
        while (true)
        {
            var received = await session.WebSocket.ReceiveAsync(buffer, session.Ending);
            if (received.MessageType == WebSocketMessageType.Close)
            {
                return;
            }

            await session.WebSocket.SendAsync(buffer.AsMemory(0, received.Count), received.MessageType, received.EndOfMessage, session.Ending);
        }
    }
}

/// <summary>
/// A serial port as an app would serve it, with the port played by a loopback: bytes sent come back.
/// <c>COM1</c> opens; <c>fault</c> opens and then reports a fault (4100); <c>busy</c> is 409; no port is
/// 422; anything else 404. 12345 baud is a rate the port cannot do. A change to 54321 baud is never
/// answered, one to 4800 only after a second. Setting DTR raises DSR and DCD.
/// </summary>
internal static class PretendSerial
{
    public const int UnsupportedBaud = 12345;

    public const int SilentBaud = 54321;

    public const int SlowBaud = 4800;

    public static ValueTask<SkakelStreamResult> OpenAsync(SkakelStreamRequest request)
    {
        var port = request.Query[SerialStreamType.PortQuery].ToString();
        return ValueTask.FromResult(port switch
        {
            "" => SkakelStreamResult.Invalid("Say which port, as ?port=<id>."),
            "busy" => SkakelStreamResult.InUse("bench-2 holds busy."),
            "COM1" or "fault" => SkakelStreamResult.Accept(session => RunAsync(session, port)),
            _ => SkakelStreamResult.NotFound($"There is no port {port}."),
        });
    }

    private static async Task RunAsync(SkakelStreamSession session, string port)
    {
        var settings = new SerialLineSettings(9600, 8, SerialParity.None, SerialStopBits.One, SerialFlowControl.None);
        await SendAsync(session, new SerialOpened(settings, new SerialModemStatus(true, false, false, false)));
        if (port == "fault")
        {
            await session.CloseAsync(SerialStreamType.PortFault, "The port reported a fault.");
            return;
        }

        var buffer = new byte[4096];
        while (true)
        {
            var received = await session.WebSocket.ReceiveAsync(buffer, session.Ending);
            switch (received.MessageType)
            {
                case WebSocketMessageType.Close:
                    return;
                case WebSocketMessageType.Binary:
                    await session.WebSocket.SendAsync(buffer.AsMemory(0, received.Count), WebSocketMessageType.Binary, received.EndOfMessage, session.Ending);
                    break;
                case WebSocketMessageType.Text when SerialMessages.TryParseClient(Encoding.UTF8.GetString(buffer, 0, received.Count), out var message):
                    switch (message)
                    {
                        case SerialSetLineSettings { Baud: UnsupportedBaud }:
                            await SendAsync(session, new SerialError(SerialErrorCode.Unsupported, $"This port cannot run at {UnsupportedBaud} baud."));
                            break;
                        case SerialSetLineSettings { Baud: SilentBaud }:
                            break;
                        case SerialSetLineSettings { Baud: SlowBaud } slow:
                            await Task.Delay(TimeSpan.FromSeconds(1), session.Ending);
                            settings = slow.ToSettings();
                            await SendAsync(session, SerialLineSettingsApplied.From(settings));
                            break;
                        case SerialSetLineSettings change:
                            settings = change.ToSettings();
                            await SendAsync(session, SerialLineSettingsApplied.From(settings));
                            break;
                        case SerialSetModemLines { Dtr: { } dtr }:
                            await SendAsync(session, new SerialModemStatusChanged(true, dtr, dtr, false));
                            break;
                    }

                    break;
            }
        }
    }

    private static Task SendAsync(SkakelStreamSession session, SerialServerMessage message) =>
        session.WebSocket.SendAsync(Encoding.UTF8.GetBytes(SerialMessages.Serialize(message)), WebSocketMessageType.Text, true, session.Ending);
}
