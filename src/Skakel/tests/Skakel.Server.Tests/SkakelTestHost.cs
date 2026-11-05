using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Connections;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Skakel.Protocol;

namespace Skakel.Server.Tests;

/// <summary>The messages the test hub sends its clients. App messages may not start with Skakel.</summary>
public interface ITestClient
{
    Task Greeted(string text);
}

/// <summary>An app's hub, as small as one gets.</summary>
public sealed class TestHub : SkakelHub<ITestClient>
{
    public Task Greet(string text) => Clients.Caller.Greeted($"{SkakelClientId}: {text}");
}

/// <summary>
/// A Skakel server on a test server, the way an app wires it: the store, the options, WebSockets,
/// <c>MapSkakel</c>, a hub at <c>/skakel/v1/hub</c> and a test stream type, <c>echo</c>. Requests go over
/// https://localhost, which a test server takes as HTTPS.
/// </summary>
internal sealed class SkakelTestHost : IAsyncDisposable
{
    public const string HubPath = "/skakel/v1/hub";
    private static readonly Uri BaseAddress = new("https://localhost/");

    private readonly WebApplication _app;

    private SkakelTestHost(WebApplication app, InMemorySkakelStore store)
    {
        _app = app;
        Store = store;
        Server = app.GetTestServer();
    }

    public TestServer Server { get; }

    public InMemorySkakelStore Store { get; }

    public IServiceProvider Services => _app.Services;

    public SkakelClients Clients => Services.GetRequiredService<SkakelClients>();

    public SkakelKeys Keys => Services.GetRequiredService<SkakelKeys>();

    public SkakelPairing Pairing => Services.GetRequiredService<SkakelPairing>();

    public static async Task<SkakelTestHost> StartAsync(Action<SkakelServerOptions>? options = null, InMemorySkakelStore? store = null, TimeProvider? time = null)
    {
        store ??= new InMemorySkakelStore();
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton<ISkakelStore>(store);
        if (time is not null)
        {
            builder.Services.AddSingleton(time);
        }

        builder.Services.AddSkakelServer(o =>
        {
            o.AppId = "test-app";
            o.AppVersion = "1.2.3";
            o.Name = "bench";
            o.Port = 5240;
            o.DiscoveryEnabled = false;
            options?.Invoke(o);
        });

        var app = builder.Build();
        app.UseWebSockets();
        app.MapSkakel();
        app.MapSkakelHub<TestHub>("hub");
        app.MapSkakelStream("echo", EchoStream.OpenAsync);
        await app.StartAsync(TestContext.Current.CancellationToken);
        return new SkakelTestHost(app, store);
    }

    public HttpClient Https()
    {
        var client = Server.CreateClient();
        client.BaseAddress = BaseAddress;
        return client;
    }

    public HttpClient PlainHttp() => Server.CreateClient();

    /// <summary>A request over HTTPS from <paramref name="from"/>, to the server under <paramref name="host"/>. The answer is in the returned context.</summary>
    public Task<HttpContext> SendFromAsync(IPAddress from, string method, string path, string? contentType = null, byte[]? body = null, string host = "localhost", string? pollToken = null) =>
        Server.SendAsync(context =>
        {
            context.Connection.RemoteIpAddress = from;
            context.Request.Scheme = "https";
            context.Request.Host = new HostString(host);
            context.Request.Method = method;
            context.Request.Path = path;
            if (pollToken is not null)
            {
                context.Request.Headers[SkakelProtocol.PairTokenHeader] = pollToken;
            }

            if (body is not null)
            {
                context.Request.ContentType = contentType;
                context.Request.ContentLength = body.Length;
                context.Request.Body = new MemoryStream(body);
            }
        });

    /// <summary>A token request from <paramref name="from"/>, answered with its status.</summary>
    public async Task<int> RequestTokenFromAsync(IPAddress from, string clientId, string secret, string host = "localhost")
    {
        var body = Encoding.ASCII.GetBytes($"grant_type=client_credentials&client_id={Uri.EscapeDataString(clientId)}&client_secret={Uri.EscapeDataString(secret)}");
        return (await SendFromAsync(from, "POST", SkakelProtocol.TokenPath, "application/x-www-form-urlencoded", body, host)).Response.StatusCode;
    }

    public async Task<HttpResponseMessage> RequestTokenAsync(string clientId, string secret, CancellationToken ct)
    {
        using var https = Https();
        return await https.PostAsync(SkakelProtocol.TokenPath, new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_secret"] = secret,
        }), ct);
    }

    public async Task<string> TokenAsync(string clientId, string secret, CancellationToken ct)
    {
        using var response = await RequestTokenAsync(clientId, secret, ct);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<JsonElement>(ct)).GetProperty("access_token").GetString()!;
    }

    public async Task<(SkakelNewClient Client, string Token)> NewClientWithTokenAsync(string name, CancellationToken ct)
    {
        var client = await Clients.RegisterAsync(name, ct);
        return (client, await TokenAsync(client.ClientId, client.ClientSecret, ct));
    }

    public async Task<HttpResponseMessage> HelloAsync(string token, CancellationToken ct)
    {
        using var https = Https();
        using var request = new HttpRequestMessage(HttpMethod.Get, SkakelProtocol.HelloPath);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await https.SendAsync(request, ct);
    }

    /// <summary>A hub connection with this token over WebSockets. Messages it receives land in the returned <see cref="HubLog"/>.</summary>
    public async Task<HubLog> ConnectHubAsync(string token, CancellationToken ct)
    {
        var connection = new HubConnectionBuilder()
            .WithUrl(new Uri(BaseAddress, HubPath), options =>
            {
                options.Transports = HttpTransportType.WebSockets;
                options.AccessTokenProvider = () => Task.FromResult<string?>(token);
                options.HttpMessageHandlerFactory = _ => Server.CreateHandler();
                options.WebSocketFactory = async (context, cancellationToken) =>
                {
                    var client = Server.CreateWebSocketClient();
                    client.ConfigureRequest = request => request.Headers.Authorization = $"Bearer {token}";
                    return await client.ConnectAsync(context.Uri, cancellationToken);
                };
            })
            .Build();
        var log = new HubLog(connection);
        await connection.StartAsync(ct);
        return log;
    }

    /// <summary>Opens a stream with this token. The socket, or the status the server refused with.</summary>
    public async Task<(WebSocket? Socket, int Status)> OpenStreamAsync(string? token, string pathAndQuery, CancellationToken ct)
    {
        var client = Server.CreateWebSocketClient();
        if (token is not null)
        {
            client.ConfigureRequest = request => request.Headers.Authorization = $"Bearer {token}";
        }

        try
        {
            return (await client.ConnectAsync(new Uri($"wss://localhost{pathAndQuery}"), ct), 101);
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("status code", StringComparison.OrdinalIgnoreCase))
        {
            return (null, int.Parse(ex.Message.Split(':')[^1].Trim(), System.Globalization.CultureInfo.InvariantCulture));
        }
    }

    public Task StopAsync() => _app.StopAsync(TestContext.Current.CancellationToken);

    public async ValueTask DisposeAsync() => await _app.DisposeAsync();
}

/// <summary>What a hub connection received, for a test to wait on.</summary>
internal sealed class HubLog
{
    private readonly TaskCompletionSource _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly List<JsonElement> _certificates = [];
    private readonly TaskCompletionSource<string> _closing = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _arrivals;

    public HubLog(HubConnection connection)
    {
        Connection = connection;
        connection.On<JsonElement>(SkakelHubMethods.Certificates, certificates =>
        {
            lock (_certificates)
            {
                _certificates.Add(certificates);
            }

            Interlocked.Increment(ref _arrivals);
        });
        connection.On<JsonElement>(SkakelHubMethods.Closing, closing => _closing.TrySetResult(closing.GetProperty("reason").GetString()!));
        connection.Closed += _ =>
        {
            _closed.TrySetResult();
            return Task.CompletedTask;
        };
    }

    public HubConnection Connection { get; }

    public Task Closed => _closed.Task;

    public Task<string> Closing => _closing.Task;

    /// <summary>Waits for a <c>SkakelCertificates</c> that satisfies <paramref name="match"/>, among those received so far and after.</summary>
    public async Task<JsonElement> CertificatesAsync(Func<JsonElement, bool> match, CancellationToken ct)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limit.CancelAfter(TimeSpan.FromSeconds(10));
        while (true)
        {
            lock (_certificates)
            {
                if (_certificates.FirstOrDefault(match) is { ValueKind: JsonValueKind.Object } found)
                {
                    return found;
                }
            }

            var seen = Volatile.Read(ref _arrivals);
            while (Volatile.Read(ref _arrivals) == seen)
            {
                await Task.Delay(10, limit.Token);
            }
        }
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
            "busy" => SkakelStreamResult.InUse("bench-1 holds busy."),
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
