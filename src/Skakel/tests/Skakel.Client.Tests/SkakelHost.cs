using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Skakel.Protocol;
using Skakel.Protocol.Serial;
using Skakel.Server;

namespace Skakel.Client.Tests;

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
/// A real Skakel server for the client to talk to: Kestrel on loopback with the server's own self-signed
/// certificate, wired the way an app wires it, with a hub at <c>/skakel/v1/hub</c>, a test stream type
/// <c>echo</c> and a pretend <c>serial</c> port.
/// </summary>
internal sealed class SkakelHost : IAsyncDisposable
{
    private readonly WebApplication _app;

    private SkakelHost(WebApplication app, InMemorySkakelStore store, int port)
    {
        _app = app;
        Store = store;
        Port = port;
    }

    public InMemorySkakelStore Store { get; }

    public int Port { get; }

    public Uri Address => new($"https://127.0.0.1:{Port}/");

    public IServiceProvider Services => _app.Services;

    public SkakelClients Clients => Services.GetRequiredService<SkakelClients>();

    public SkakelKeys Keys => Services.GetRequiredService<SkakelKeys>();

    public Skakel.Server.SkakelPairing Pairing => Services.GetRequiredService<Skakel.Server.SkakelPairing>();

    public SkakelSessions Sessions => Services.GetRequiredService<SkakelSessions>();

    public SkakelPins Pins => new(Keys.Fingerprint);

    /// <summary>When set, <c>/skakel/info</c> lists these versions instead, as a server of another version would.</summary>
    public IReadOnlyList<int>? InfoVersions { get; set; }

    /// <summary>When set, the token endpoint says its tokens last this many seconds, whatever they really do.</summary>
    public int? TokenExpiresIn { get; set; }

    /// <summary>How many tokens the token endpoint handed out.</summary>
    public int Tokens => Volatile.Read(ref _tokens);

    /// <summary>How many times a client started a hub connection.</summary>
    public int Negotiates => Volatile.Read(ref _negotiates);

    private int _tokens;
    private int _negotiates;

    /// <param name="store">The server's state; a second server given the same store has the same certificate and clients.</param>
    /// <param name="port">The TCP port; a free one unless given.</param>
    /// <param name="discoveryPort">Answers discovery on this UDP port; off unless given.</param>
    public static async Task<SkakelHost> StartAsync(InMemorySkakelStore? store = null, int? port = null, int? discoveryPort = null)
    {
        store ??= new InMemorySkakelStore();
        var tcp = port ?? Ports.FreeTcp();
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
        SkakelHost? host = null;
        app.Use(async (http, next) =>
        {
            if (host?.InfoVersions is { } versions && http.Request.Path == SkakelProtocol.InfoPath)
            {
                await http.Response.WriteAsJsonAsync(new SkakelInfo("bench", new SkakelApp("test-app", "9.0.0"), versions), SkakelJson.Options);
                return;
            }

            if (host is not null && http.Request.Path.StartsWithSegments("/skakel/v1/hub/negotiate"))
            {
                Interlocked.Increment(ref host._negotiates);
            }

            if (host is not null && http.Request.Path == SkakelProtocol.TokenPath)
            {
                Interlocked.Increment(ref host._tokens);
                if (host.TokenExpiresIn is { } expiresIn)
                {
                    await RewriteExpiresInAsync(http, next, expiresIn);
                    return;
                }
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
        await app.StartAsync(TestContext.Current.CancellationToken);
        host = new SkakelHost(app, store, tcp);
        return host;
    }

    public async Task<SkakelCredentials> RegisterAsync(string name = "bench-1")
    {
        var client = await Clients.RegisterAsync(name, TestContext.Current.CancellationToken);
        return new SkakelCredentials(client.ClientId, client.ClientSecret);
    }

    /// <summary>A link to this server with new credentials, not started.</summary>
    public async Task<(SkakelLink Link, SkakelCredentials Credentials)> LinkAsync(SkakelClientOptions? options = null)
    {
        var credentials = await RegisterAsync();
        return (new SkakelLink(Address, Pins, credentials, options), credentials);
    }

    public Task StopAsync() => _app.StopAsync(TestContext.Current.CancellationToken);

    public async ValueTask DisposeAsync() => await _app.DisposeAsync();

    /// <summary>The real token answer, with <c>expires_in</c> replaced.</summary>
    private static async Task RewriteExpiresInAsync(HttpContext http, RequestDelegate next, int expiresIn)
    {
        var original = http.Response.Body;
        using var buffer = new MemoryStream();
        http.Response.Body = buffer;
        await next(http);
        http.Response.Body = original;
        var answer = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(buffer.ToArray())!;
        var rewritten = answer.ToDictionary(p => p.Key, p => p.Key == "expires_in" ? (object)expiresIn : p.Value);
        http.Response.ContentLength = null;
        await http.Response.WriteAsJsonAsync(rewritten);
    }
}

/// <summary>
/// A server that is not a Skakel server: Kestrel on loopback with a certificate of its own, answering
/// what the test maps, for answers a real server would never give.
/// </summary>
internal sealed class FakeServer : IAsyncDisposable
{
    private readonly WebApplication _app;

    private FakeServer(WebApplication app, int port, string fingerprint)
    {
        _app = app;
        Address = new Uri($"https://127.0.0.1:{port}/");
        Fingerprint = fingerprint;
    }

    public Uri Address { get; }

    public string Fingerprint { get; }

    public SkakelPins Pins => new(Fingerprint);

    public static async Task<FakeServer> StartAsync(Action<WebApplication> map)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=fake", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(10));
        var certificate = X509CertificateLoader.LoadPkcs12(created.Export(X509ContentType.Pfx), null);
        var port = Ports.FreeTcp();
        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(IPAddress.Loopback, port, listen => listen.UseHttps(certificate)));
        var app = builder.Build();
        map(app);
        await app.StartAsync(TestContext.Current.CancellationToken);
        return new FakeServer(app, port, Fingerprints.Of(certificate));
    }

    /// <summary>Info as a Skakel server of the test app gives it.</summary>
    public static IResult Info(string name = "fake") => Results.Json(new SkakelInfo(name, new SkakelApp("test-app", "1"), [1]), SkakelJson.Options);

    public async ValueTask DisposeAsync() => await _app.DisposeAsync();
}

/// <summary>A plain TCP listener on loopback that records what arrives and answers nothing, or what it is told to.</summary>
internal sealed class Listener : IDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly List<string> _received = [];

    public Listener(string? answer = null)
    {
        _listener.Start();
        _ = AcceptAsync(answer);
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    /// <summary>Everything any connection sent, as text.</summary>
    public string Received
    {
        get
        {
            lock (_received)
            {
                return string.Concat(_received);
            }
        }
    }

    public void Dispose() => _listener.Stop();

    private async Task AcceptAsync(string? answer)
    {
        try
        {
            while (true)
            {
                var client = await _listener.AcceptTcpClientAsync();
                _ = ServeAsync(client, answer);
            }
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
        {
            // Stopped.
        }
    }

    private async Task ServeAsync(TcpClient client, string? answer)
    {
        using var _ = client;
        var buffer = new byte[4096];
        try
        {
            var stream = client.GetStream();
            int read;
            while ((read = await stream.ReadAsync(buffer)) > 0)
            {
                lock (_received)
                {
                    _received.Add(Encoding.Latin1.GetString(buffer, 0, read));
                }

                if (answer is not null)
                {
                    await stream.WriteAsync(Encoding.ASCII.GetBytes(answer));
                }
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
        {
            // The other end went.
        }
    }
}

/// <summary>Free ports on loopback, for a server that has to know its own before it starts.</summary>
internal static class Ports
{
    public static int FreeTcp()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    public static int FreeUdp()
    {
        using var socket = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
        return ((IPEndPoint)socket.Client.LocalEndPoint!).Port;
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

/// <summary>What an event raised, for a test to wait on.</summary>
internal sealed class Recorder<T>
{
    private readonly List<T> _seen = [];
    private int _arrivals;

    public IReadOnlyList<T> Seen
    {
        get
        {
            lock (_seen)
            {
                return [.. _seen];
            }
        }
    }

    public Task Record(T value)
    {
        lock (_seen)
        {
            _seen.Add(value);
        }

        Interlocked.Increment(ref _arrivals);
        return Task.CompletedTask;
    }

    /// <summary>The first value, among those seen so far and after, that satisfies <paramref name="match"/>.</summary>
    public async Task<T> WaitAsync(Func<T, bool> match, TimeSpan? timeout = null)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        limit.CancelAfter(timeout ?? TimeSpan.FromSeconds(15));
        while (true)
        {
            var seen = Volatile.Read(ref _arrivals);
            lock (_seen)
            {
                foreach (var value in _seen)
                {
                    if (match(value))
                    {
                        return value;
                    }
                }
            }

            while (Volatile.Read(ref _arrivals) == seen)
            {
                await Task.Delay(10, limit.Token);
            }
        }
    }
}
