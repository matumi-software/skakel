using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Skakel.Protocol;
using Skakel.Protocol.Serial;

namespace Skakel.Client;

/// <summary>Where a link stands.</summary>
public enum SkakelLinkState
{
    /// <summary>Not started, or stopped.</summary>
    Stopped,

    /// <summary>Connecting, the first time or again after a failure.</summary>
    Connecting,

    /// <summary>The hub is connected. Renewing it before its token runs out does not leave this state.</summary>
    Connected,

    /// <summary>The last attempt failed, or the connection was lost; the link tries again after a pause.</summary>
    Failed,

    /// <summary>The server ended the client for good (revoked, or its secret rotated). The link does not try again.</summary>
    Closed,
}

/// <summary>Where a link stands, and why when it is not connected.</summary>
/// <param name="State">The state.</param>
/// <param name="Failure">What went wrong, in <see cref="SkakelLinkState.Failed"/> and <see cref="SkakelLinkState.Closed"/>.</param>
public sealed record SkakelLinkStatus(SkakelLinkState State, SkakelFailure? Failure = null);

/// <summary>
/// A client's link to one server: a handler pinned to the server's certificates, a token client, the
/// control hub, and the streams. An app holds one per server it is paired with.
/// </summary>
/// <remarks>
/// <para>
/// The app keeps the address, the pins and the credentials, and hands them in. What changes goes back
/// out as events: <see cref="PinsChanged"/> during a certificate handover, <see cref="AddressChanged"/>
/// when the server moved on the local network. Save the new values in the handler; a handler that throws
/// is taken as not saved.
/// </para>
/// <para>
/// Once started, the link keeps the hub connected: it reads <c>/skakel/info</c> to check the version,
/// connects with a token, connects again with a fresh token 30 seconds before the token runs out without
/// saying so, and after a failure tries again with a pause that grows to a minute. Two connections never
/// start less than a second apart, and a token is taken to last 2 to 30 minutes whatever the server
/// says. A revoke or rotation on the server ends it for good, as <see cref="SkakelLinkState.Closed"/>.
/// </para>
/// </remarks>
public sealed partial class SkakelLink : IAsyncDisposable
{
    /// <summary>How long before a token runs out the hub connects again with a fresh one.</summary>
    internal static readonly TimeSpan RefreshAhead = TimeSpan.FromSeconds(30);

    /// <summary>A close this close to the token's end is the server's expiry, not a failure.</summary>
    internal static readonly TimeSpan ExpiryGrace = TimeSpan.FromSeconds(10);

    internal static readonly TimeSpan MinBackoff = TimeSpan.FromSeconds(1);

    internal static readonly TimeSpan MaxBackoff = TimeSpan.FromSeconds(60);

    /// <summary>The longest the link waits to renew, well inside what a timer can count.</summary>
    internal static readonly TimeSpan MaxRenewWait = SkakelProtocol.AccessTokenLifetime;

    private readonly SkakelClientOptions _options;
    private readonly ILogger _logger;
    private readonly TimeProvider _time;
    private readonly string _hubPath;
    private readonly SocketsHttpHandler _handler;
    private readonly BearerHandler _bearer;
    private readonly HttpClient _http;
    private readonly HttpMessageInvoker _streams;
    private readonly TokenClient _tokens;
    private readonly ServerMoves _moves;
    private readonly HubHandlers _handlers = new();
    private readonly SkakelBrowser? _browser;
    private readonly IDisposable? _protection;
    private readonly Lock _gate = new();

    private Uri _address;
    private SkakelPins _pins;
    private SkakelLinkStatus _status = new(SkakelLinkState.Stopped);
    private HubConnection? _hub;
    private TaskCompletionSource _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private TaskCompletionSource _wake = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private CancellationTokenSource? _run;
    private Task _running = Task.CompletedTask;
    private bool _stranded;
    private Task _following = Task.CompletedTask;
    private bool _followRunning;
    private bool _followAgain;
    private bool _disposed;

    /// <summary>A link to a server. Call <see cref="Start"/> to connect the hub; the streams and requests work without it.</summary>
    /// <param name="address">The server's HTTPS address, as the app saved it.</param>
    /// <param name="pins">The server's certificates, as the app saved them.</param>
    /// <param name="credentials">The client's credentials on that server.</param>
    /// <param name="options">Logging, time, the hub's path and the browser to follow the server with.</param>
    public SkakelLink(Uri address, SkakelPins pins, SkakelCredentials credentials, SkakelClientOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(pins);
        ArgumentNullException.ThrowIfNull(credentials);
        _address = Pinning.BaseAddress(address, nameof(address));
        _pins = pins;
        Credentials = credentials;
        _options = options ?? new SkakelClientOptions();
        _hubPath = HubPath(_options.HubPath);
        _logger = _options.Loggers.CreateLogger<SkakelLink>();
        _time = _options.Time;
        _handler = Pinning.CreateHandler(() => Pins);
        _bearer = new BearerHandler(this, _handler);
        _http = Pinning.CreateClient(_handler, _options.RequestTimeout, disposeHandler: false);
        _streams = new HttpMessageInvoker(_handler, disposeHandler: false);
        _tokens = new TokenClient(_http, () => Address, credentials, _time);
        _moves = new ServerMoves(_time, _logger);
        _browser = _options.Browser;
        _protection = _browser?.Protect(() => Pins);
        _browser?.Changed += OnServersChangedAsync;
    }

    /// <summary>Raised when the state changes. Renewing the hub before its token runs out is not a change.</summary>
    public event Func<SkakelLinkStatus, Task>? StatusChanged;

    /// <summary>
    /// Raised when the server told the link about its certificates and the pins changed: a next one to
    /// trust as well, a switch to it, or a cancelled one. Save the pins in the handler. Only once every
    /// handler returned does the link tell the server it has the next certificate.
    /// </summary>
    public event Func<SkakelPins, Task>? PinsChanged;

    /// <summary>Raised when the server moved on the local network and the link followed it. Save the address in the handler.</summary>
    public event Func<Uri, Task>? AddressChanged;

    /// <summary>The server's address. It changes when the link follows the server to another one.</summary>
    public Uri Address
    {
        get
        {
            lock (_gate)
            {
                return _address;
            }
        }
    }

    /// <summary>The certificates the link trusts now.</summary>
    public SkakelPins Pins
    {
        get
        {
            lock (_gate)
            {
                return _pins;
            }
        }
    }

    /// <summary>The credentials the link signs in with.</summary>
    public SkakelCredentials Credentials { get; }

    /// <summary>Where the link stands.</summary>
    public SkakelLinkStatus Status
    {
        get
        {
            lock (_gate)
            {
                return _status;
            }
        }
    }

    /// <summary>Starts keeping the hub connected, in the background. <see cref="StatusChanged"/> reports how it goes. Starting a started link does nothing.</summary>
    public void Start()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_run is not null)
            {
                return;
            }

            var run = new CancellationTokenSource();
            _run = run;
            _running = Task.Run(() => RunAsync(run.Token), CancellationToken.None);
        }
    }

    /// <summary>Closes the hub and stops trying. Streams already open carry on.</summary>
    public async Task StopAsync()
    {
        CancellationTokenSource? run;
        Task running;
        lock (_gate)
        {
            run = _run;
            running = _running;
            _run = null;
        }

        if (run is null)
        {
            return;
        }

        await run.CancelAsync();
        await running.ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
        await Following.ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
        run.Dispose();
        await SetStatusAsync(new SkakelLinkStatus(SkakelLinkState.Stopped));
    }

    /// <summary>Stops, and lets go of the connections.</summary>
    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
        }

        _browser?.Changed -= OnServersChangedAsync;
        _protection?.Dispose();

        _http.Dispose();
        _streams.Dispose();
        _bearer.Dispose();
        _tokens.Dispose();
        _moves.Dispose();
    }

    /// <summary>
    /// Checks the version and the credentials with <c>GET /skakel/v1/hello</c>, as an app's Test button
    /// does. Works whether the link is started or not.
    /// </summary>
    /// <param name="cancellationToken">Cancels the check.</param>
    /// <exception cref="SkakelException">One of the fixed failures: unreachable, certificate mismatch, version mismatch, rejected credentials, client unknown, and so on.</exception>
    public async Task<SkakelHello> HelloAsync(CancellationToken cancellationToken = default)
    {
        var address = Address;
        try
        {
            var info = await SkakelInfoClient.ReadAsync(_http, address, _logger, cancellationToken);
            SkakelVersions.Require(info.Versions);
            var (token, _) = await _tokens.GetAsync(cancellationToken);
            using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(address, SkakelProtocol.HelloPath));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var response = await _http.SendAsync(request, cancellationToken);
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                _tokens.Forget(token);
            }

            response.EnsureSuccessStatusCode();
            return await response.Content.ReadFromJsonAsync<SkakelHello>(SkakelJson.Options, cancellationToken) is { Server: not null, ClientId: not null } hello
                ? hello
                : throw new InvalidDataException("The hello answer is missing the server or the client.");
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            LogCallFailed(address.Authority, "hello", ex);
            throw Failures.Exception(ex);
        }
    }

    /// <summary>A token for this server, reused until shortly before it runs out. For a call the link does not make itself.</summary>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <exception cref="SkakelException">The server could not be reached, or refused the credentials.</exception>
    public async Task<string> GetAccessTokenAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            return (await _tokens.GetAsync(cancellationToken)).Token;
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            LogCallFailed(Address.Authority, "token", ex);
            throw Failures.Exception(ex);
        }
    }

    /// <summary>
    /// An HTTP client for the app's own endpoints on this server: pinned, with the link's token on every
    /// request, and the server's address as its base. It sends only to the server's current address over
    /// HTTPS; a request anywhere else throws <see cref="InvalidOperationException"/> before anything is
    /// sent, so the token cannot leave for another host. Make a new one after <see cref="AddressChanged"/>.
    /// Disposing it leaves the link as it is.
    /// </summary>
    public HttpClient CreateHttpClient()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
        }

        return new HttpClient(_bearer, disposeHandler: false) { BaseAddress = Address, Timeout = _options.RequestTimeout };
    }

    /// <summary>Handles one of the app's own hub messages, on every hub connection the link makes.</summary>
    /// <param name="methodName">The message's name. It may not start with <c>Skakel</c>.</param>
    /// <param name="parameterTypes">The types of its arguments.</param>
    /// <param name="handler">Runs with the arguments, one message at a time.</param>
    /// <returns>Disposing it stops handling the message.</returns>
    public IDisposable On(string methodName, Type[] parameterTypes, Func<object?[], Task> handler)
    {
        CheckName(methodName);
        ArgumentNullException.ThrowIfNull(parameterTypes);
        ArgumentNullException.ThrowIfNull(handler);
        return _handlers.Add(methodName, parameterTypes, handler);
    }

    /// <summary>Handles one of the app's own hub messages that has no arguments.</summary>
    /// <param name="methodName">The message's name.</param>
    /// <param name="handler">Runs for each message.</param>
    public IDisposable On(string methodName, Func<Task> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        return On(methodName, [], _ => handler());
    }

    /// <summary>Handles one of the app's own hub messages that has one argument.</summary>
    /// <typeparam name="T1">The argument's type.</typeparam>
    /// <param name="methodName">The message's name.</param>
    /// <param name="handler">Runs for each message.</param>
    public IDisposable On<T1>(string methodName, Func<T1, Task> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        return On(methodName, [typeof(T1)], a => handler((T1)a[0]!));
    }

    /// <summary>Handles one of the app's own hub messages that has two arguments.</summary>
    /// <typeparam name="T1">The first argument's type.</typeparam>
    /// <typeparam name="T2">The second argument's type.</typeparam>
    /// <param name="methodName">The message's name.</param>
    /// <param name="handler">Runs for each message.</param>
    public IDisposable On<T1, T2>(string methodName, Func<T1, T2, Task> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        return On(methodName, [typeof(T1), typeof(T2)], a => handler((T1)a[0]!, (T2)a[1]!));
    }

    /// <summary>Calls one of the app's own hub methods and waits for its result.</summary>
    /// <typeparam name="TResult">What it returns.</typeparam>
    /// <param name="methodName">The method's name. It may not start with <c>Skakel</c>.</param>
    /// <param name="arguments">Its arguments.</param>
    /// <param name="cancellationToken">Stops waiting.</param>
    /// <exception cref="SkakelException">The link is not connected, or the connection was lost during the call.</exception>
    public async Task<TResult> InvokeAsync<TResult>(string methodName, object?[]? arguments = null, CancellationToken cancellationToken = default)
    {
        CheckName(methodName);
        var hub = await ConnectedHubAsync(cancellationToken);
        try
        {
            return (TResult)(await hub.InvokeCoreAsync(methodName, typeof(TResult), arguments ?? [], cancellationToken))!;
        }
        catch (InvalidOperationException ex) when (hub.State != HubConnectionState.Connected)
        {
            throw new SkakelException(SkakelFailureKind.ConnectionLost, ex);
        }
    }

    /// <summary>Calls one of the app's own hub methods and waits until it has run.</summary>
    /// <param name="methodName">The method's name. It may not start with <c>Skakel</c>.</param>
    /// <param name="arguments">Its arguments.</param>
    /// <param name="cancellationToken">Stops waiting.</param>
    /// <exception cref="SkakelException">The link is not connected, or the connection was lost during the call.</exception>
    public async Task InvokeAsync(string methodName, object?[]? arguments = null, CancellationToken cancellationToken = default)
    {
        CheckName(methodName);
        var hub = await ConnectedHubAsync(cancellationToken);
        try
        {
            await hub.InvokeCoreAsync(methodName, arguments ?? [], cancellationToken);
        }
        catch (InvalidOperationException ex) when (hub.State != HubConnectionState.Connected)
        {
            throw new SkakelException(SkakelFailureKind.ConnectionLost, ex);
        }
    }

    /// <summary>Sends one of the app's own hub messages without waiting for it to run.</summary>
    /// <param name="methodName">The method's name. It may not start with <c>Skakel</c>.</param>
    /// <param name="arguments">Its arguments.</param>
    /// <param name="cancellationToken">Cancels the send.</param>
    /// <exception cref="SkakelException">The link is not connected, or the connection was lost.</exception>
    public async Task SendAsync(string methodName, object?[]? arguments = null, CancellationToken cancellationToken = default)
    {
        CheckName(methodName);
        var hub = await ConnectedHubAsync(cancellationToken);
        try
        {
            await hub.SendCoreAsync(methodName, arguments ?? [], cancellationToken);
        }
        catch (InvalidOperationException ex) when (hub.State != HubConnectionState.Connected)
        {
            throw new SkakelException(SkakelFailureKind.ConnectionLost, ex);
        }
    }

    /// <summary>
    /// Opens a stream at <c>/skakel/v1/streams/{type}</c> with the link's token. What the stream is for
    /// goes in <paramref name="query"/>, as the type defines it. A refusal before the upgrade comes back
    /// in the result, with the server's status and its words for it.
    /// </summary>
    /// <param name="type">The stream type: one or more of <c>a-z</c>, <c>0-9</c> and <c>-</c>.</param>
    /// <param name="query">The query string's parameters.</param>
    /// <param name="cancellationToken">Cancels opening.</param>
    /// <exception cref="SkakelException">The server could not be reached, presented another certificate, or refused the credentials.</exception>
    public async Task<SkakelOpenResult<SkakelStreamConnection>> OpenStreamAsync(string type, IEnumerable<KeyValuePair<string, string>>? query = null, CancellationToken cancellationToken = default)
    {
        if (!SkakelProtocol.IsStreamType(type))
        {
            throw new ArgumentException("A stream type is one or more of a-z, 0-9 and -.", nameof(type));
        }

        var address = Address;
        var uri = StreamOpener.Path(address, type, query);
        try
        {
            for (var attempt = 1; ; attempt++)
            {
                var (token, _) = await _tokens.GetAsync(cancellationToken);
                var result = await StreamOpener.OpenAsync(_streams, uri, type, token, _options.RequestTimeout, cancellationToken);
                if (result.Refusal is { Reason: SkakelStreamRefusalReason.Unauthorized } && attempt == 1)
                {
                    // The token may have just run out on the server's clock; one more try with a fresh one.
                    _tokens.Forget(token);
                    continue;
                }

                if (result.Refusal is { } refusal)
                {
                    LogStreamRefused(type, address.Authority, refusal.Status, refusal.Message);
                }

                return result;
            }
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            LogCallFailed(address.Authority, type, ex);
            throw Failures.Exception(ex);
        }
    }

    /// <summary>
    /// Opens a <c>serial</c> stream to the port with this id in the app's list of ports, and waits for the
    /// server to say the port is open. A second client gets a refusal with 409.
    /// </summary>
    /// <param name="portId">The port's id.</param>
    /// <param name="cancellationToken">Cancels opening.</param>
    /// <exception cref="SkakelException">The server could not be reached, refused the credentials, or did not open the port.</exception>
    public async Task<SkakelOpenResult<SkakelSerialConnection>> OpenSerialAsync(string portId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(portId);
        var opened = await OpenStreamAsync(SerialStreamType.Type, [new(SerialStreamType.PortQuery, portId)], cancellationToken);
        if (!opened.IsOpen)
        {
            return SkakelOpenResult<SkakelSerialConnection>.Refused(opened.Refusal);
        }

        try
        {
            return SkakelOpenResult<SkakelSerialConnection>.Opened(await SkakelSerialConnection.StartAsync(opened.Stream, _logger, cancellationToken));
        }
        catch (Exception ex)
        {
            LogCallFailed(Address.Authority, SerialStreamType.Type, ex);
            await opened.Stream.DisposeAsync();
            throw;
        }
    }

    /// <summary>The path under <c>/skakel/v1/</c>, checked as the server checks it.</summary>
    private static string HubPath(string path)
    {
        var relative = path?.Trim('/');
        if (string.IsNullOrEmpty(relative) || relative.Split('/')[0] is "pair" or "token" or "hello" or "streams")
        {
            throw new ArgumentException("The hub's path is the app's own, under /skakel/v1/, such as hub.", nameof(path));
        }

        return relative;
    }

    private static void CheckName(string methodName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(methodName);
        if (methodName.StartsWith(SkakelHubMethods.Prefix, StringComparison.Ordinal))
        {
            throw new ArgumentException($"Names that start with {SkakelHubMethods.Prefix} are Skakel's own.", nameof(methodName));
        }
    }

    /// <summary>The search for a server that moved, while one runs; for a test to wait on.</summary>
    internal Task Following
    {
        get
        {
            lock (_gate)
            {
                return _following;
            }
        }
    }

    /// <summary>The live hub connection. While the link is connected and renewing, waits for the new one.</summary>
    private async Task<HubConnection> ConnectedHubAsync(CancellationToken cancellationToken)
    {
        Task ready;
        lock (_gate)
        {
            if (_status.State != SkakelLinkState.Connected)
            {
                throw new SkakelException(SkakelFailureKind.NotConnected);
            }

            ready = _ready.Task;
        }

        await ready.WaitAsync(cancellationToken);
        lock (_gate)
        {
            return _hub ?? throw new SkakelException(SkakelFailureKind.NotConnected);
        }
    }

    /// <summary>Keeps the hub connected until stopped. Catches everything: a link fails visibly, never silently.</summary>
    private async Task RunAsync(CancellationToken stop)
    {
        var backoff = MinBackoff;
        var refreshing = false;
        var started = DateTimeOffset.MinValue;
        while (!stop.IsCancellationRequested)
        {
            var address = Address;
            try
            {
                // Whatever a server's tokens or closes say, connections start at most once a second.
                var since = _time.GetUtcNow() - started;
                if (since < MinBackoff)
                {
                    await PauseAsync(MinBackoff - since, stop);
                    address = Address;
                }

                started = _time.GetUtcNow();
                var end = await ConnectOnceAsync(address, refreshing, stop);
                refreshing = end is null;
                if (end is null)
                {
                    backoff = MinBackoff;
                    continue;
                }

                if (end.Kind is SkakelFailureKind.Revoked or SkakelFailureKind.Rotated)
                {
                    LogEnded(address.Authority, end.Code);
                    await SetStatusAsync(new SkakelLinkStatus(SkakelLinkState.Closed, end));
                    return;
                }

                // It was up; whatever ended it, the next try comes soon.
                LogLost(address.Authority, end.Code);
                await SetStatusAsync(new SkakelLinkStatus(SkakelLinkState.Failed, end));
                backoff = MinBackoff;
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                refreshing = false;
                var failure = Failures.From(ex);
                LogLinkFailed(address.Authority, failure.Code, ex);
                await SetStatusAsync(new SkakelLinkStatus(SkakelLinkState.Failed, failure));
                if (Failures.IsUnreachable(ex) && _browser is not null)
                {
                    lock (_gate)
                    {
                        _stranded = true;
                    }

                    RequestFollow();
                }
            }

            try
            {
                await PauseAsync(backoff, stop);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            backoff = TimeSpan.FromTicks(Math.Min(backoff.Ticks * 2, MaxBackoff.Ticks));
        }
    }

    /// <summary>
    /// One hub connection, from start to end. Null when it ended because its token is about to run out, so
    /// the next one is a renewal nobody hears of; otherwise why it ended. Throws when it could not connect.
    /// </summary>
    private async Task<SkakelFailure?> ConnectOnceAsync(Uri address, bool refreshing, CancellationToken stop)
    {
        if (!refreshing)
        {
            await SetStatusAsync(new SkakelLinkStatus(SkakelLinkState.Connecting));
            var info = await SkakelInfoClient.ReadAsync(_http, address, _logger, stop);
            SkakelVersions.Require(info.Versions);
        }

        var attempt = new Attempt();
        var hub = BuildHub(address, attempt, stop);
        try
        {
            try
            {
                await hub.StartAsync(stop);
            }
            catch (HttpRequestException ex) when (ex.StatusCode == HttpStatusCode.Unauthorized && attempt.Token is { } refused)
            {
                _tokens.Forget(refused);
                throw;
            }

            lock (_gate)
            {
                _hub = hub;
                _ready.TrySetResult();
                _stranded = false;
            }

            if (refreshing)
            {
                LogRenewed(address.Authority);
            }
            else
            {
                LogConnected(address.Authority);
            }

            await SetStatusAsync(new SkakelLinkStatus(SkakelLinkState.Connected));

            using var armed = CancellationTokenSource.CreateLinkedTokenSource(stop);
            var wait = new DateTimeOffset(attempt.RefreshAt, TimeSpan.Zero) - _time.GetUtcNow();
            var refresh = Task.Delay(TimeSpan.FromTicks(Math.Clamp(wait.Ticks, 0, MaxRenewWait.Ticks)), _time, armed.Token);
            var finished = await Task.WhenAny(attempt.Closed.Task, refresh);
            await armed.CancelAsync();
            stop.ThrowIfCancellationRequested();
            if (finished == refresh)
            {
                return null;
            }

            switch (attempt.Closing)
            {
                case SkakelClosingReasons.Revoked:
                    return SkakelFailure.Of(SkakelFailureKind.Revoked);
                case SkakelClosingReasons.Rotated:
                    return SkakelFailure.Of(SkakelFailureKind.Rotated);
                case SkakelClosingReasons.Stopping:
                    return SkakelFailure.Of(SkakelFailureKind.ServerStopping);
            }

            if (_time.GetUtcNow().UtcTicks >= attempt.ExpiresAt - ExpiryGrace.Ticks)
            {
                // The server closed it at the token's end, a little before the renewal was due.
                return null;
            }

            if (await attempt.Closed.Task is { } error)
            {
                LogClosedWithError(address.Authority, error);
            }

            return SkakelFailure.Of(SkakelFailureKind.ConnectionLost);
        }
        finally
        {
            lock (_gate)
            {
                if (ReferenceEquals(_hub, hub))
                {
                    _hub = null;
                }

                if (_ready.Task.IsCompleted)
                {
                    _ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                }
            }

            _handlers.Detach(hub);
            await hub.DisposeAsync();
        }
    }

    private HubConnection BuildHub(Uri address, Attempt attempt, CancellationToken stop)
    {
        var builder = new HubConnectionBuilder()
            .WithUrl(new Uri(address, $"{SkakelProtocol.BasePath}/{_hubPath}"), options =>
            {
                options.AccessTokenProvider = async () =>
                {
                    var (token, expiresAt) = await _tokens.GetAsync(stop);
                    var left = expiresAt - _time.GetUtcNow();
                    // Half a minute ahead; a token with less than a minute left is renewed halfway through what it has.
                    var margin = TimeSpan.FromTicks(Math.Min(RefreshAhead.Ticks, left.Ticks / 2));
                    attempt.Token = token;
                    attempt.RefreshAt = (expiresAt - margin).UtcTicks;
                    attempt.ExpiresAt = expiresAt.UtcTicks;
                    return token;
                };
                // Kept to the server's address, with no proxy, as every other request the link makes.
                options.HttpMessageHandlerFactory = _ => Pinning.CreateHubHandler(address, () => Pins, presented => attempt.Presented = presented);
                options.WebSocketConfiguration = socket =>
                {
                    socket.Proxy = null;
                    socket.RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                        Pinning.Trusts(Pins, certificate as X509Certificate2, presented => attempt.Presented = presented);
                };
            });
        builder.Services.AddSingleton(_options.Loggers);
        if (_options.ConfigureHubJson is { } configure)
        {
            builder.AddJsonProtocol(json => configure(json.PayloadSerializerOptions));
        }

        var hub = builder.Build();
        hub.On<SkakelCertificates>(SkakelHubMethods.Certificates, certificates => LearnCertificatesAsync(hub, address, attempt, certificates));
        hub.On<SkakelClosing>(SkakelHubMethods.Closing, closing =>
        {
            attempt.Closing = closing?.Reason;
            LogClosing(address.Authority, closing?.Reason ?? "?");
            return Task.CompletedTask;
        });
        hub.Closed += error =>
        {
            attempt.Closed.TrySetResult(error);
            return Task.CompletedTask;
        };
        _handlers.AttachAll(hub);
        return hub;
    }

    /// <summary>
    /// The server told the link which certificate it presents and which one it will switch to. The link is
    /// pinned to a certificate it trusts, so it may vouch for the next one: it is trusted as well, or becomes
    /// the pinned one once the server presents it. Once the app saved the pins, the server is told the
    /// client has the next one. A fingerprint that is not one is ignored. So is a statement about a
    /// certificate this connection did not present, unless a new connection to the server presents it,
    /// as after a switch, when the hub connection still runs on the old certificate.
    /// </summary>
    private async Task LearnCertificatesAsync(HubConnection hub, Uri address, Attempt attempt, SkakelCertificates? certificates)
    {
        if (certificates is null || Fingerprints.Normalize(certificates.Fingerprint) is null
            || (certificates.NextFingerprint is not null && Fingerprints.Normalize(certificates.NextFingerprint) is null))
        {
            LogInvalidCertificates();
            return;
        }

        if (!Fingerprints.AreEqual(certificates.Fingerprint, attempt.Presented) && !await PresentsAsync(address, certificates.Fingerprint))
        {
            LogCertificatesNotPresented(certificates.Fingerprint);
            return;
        }

        SkakelPins before;
        SkakelPins after;
        lock (_gate)
        {
            before = _pins;
            after = before.WithServerCertificates(certificates.Fingerprint, certificates.NextFingerprint);
            _pins = after;
        }

        if (after != before)
        {
            LogPinsChanged(after.Fingerprint, after.NextFingerprint ?? "none");
            if (!await PinsChanged.TryRaiseAsync(after, _logger))
            {
                // Not saved: the server is not told, and says it again on the next connection.
                return;
            }
        }

        if (after.NextFingerprint is { } next && Fingerprints.AreEqual(next, certificates.NextFingerprint))
        {
            try
            {
                // Sent, not invoked: a handler that waits for an answer would hold up the messages that bring it.
                await hub.SendCoreAsync(SkakelHubMethods.NextCertificateReceived, [next]);
            }
            catch (Exception ex) when (ex is InvalidOperationException or IOException or HttpRequestException)
            {
                LogCallFailed(Address.Authority, SkakelHubMethods.NextCertificateReceived, ex);
            }
        }
    }

    /// <summary>The list of servers changed; a link that cannot reach its server looks for it there, in the background.</summary>
    private Task OnServersChangedAsync(IReadOnlyList<SkakelDiscoveredServer> servers)
    {
        RequestFollow();
        return Task.CompletedTask;
    }

    /// <summary>
    /// Starts a search for the server in the background, while the link cannot reach it. A request while
    /// one runs has it look once more when it is done, at the addresses heard by then, so searches never
    /// pile up and a slow proof never holds up the browser's other listeners.
    /// </summary>
    private void RequestFollow()
    {
        lock (_gate)
        {
            if (!_stranded || _run is not { } run || _browser is not { } browser)
            {
                return;
            }

            if (_followRunning)
            {
                _followAgain = true;
                return;
            }

            _followRunning = true;
            var stop = run.Token;
            _following = Task.Run(() => FollowWhileAskedAsync(browser, stop), CancellationToken.None);
        }
    }

    private async Task FollowWhileAskedAsync(SkakelBrowser browser, CancellationToken stop)
    {
        while (true)
        {
            try
            {
                await FollowAsync(Address, browser.Entries, stop);
            }
            catch (OperationCanceledException)
            {
                // Stopped meanwhile.
            }

            lock (_gate)
            {
                if (!_followAgain || !_stranded || stop.IsCancellationRequested)
                {
                    _followAgain = false;
                    _followRunning = false;
                    return;
                }

                _followAgain = false;
            }
        }
    }

    /// <summary>Moves the link to where its server is now, if discovery heard it elsewhere and it proved it holds the certificate.</summary>
    private async Task FollowAsync(Uri from, IReadOnlyList<SkakelDiscoveredServer> servers, CancellationToken stop)
    {
        try
        {
            var to = await _moves.FindAsync(from, Pins, servers, url => ProvesAsync(url, stop), stop);
            if (to is null)
            {
                return;
            }

            lock (_gate)
            {
                if (_address != from)
                {
                    return;
                }

                _address = to;
                _stranded = false;
                _wake.TrySetResult();
            }

            LogMoved(from.Authority, to.Authority);
            await AddressChanged.RaiseAsync(to, _logger);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Nothing moved; the next failure or the next list tries again.
            LogMoveFailed(ex);
        }
    }

    /// <summary>
    /// Whether <paramref name="url"/> holds a certificate the link trusts: <c>GET /skakel/info</c> over the
    /// pinned handler, with no token, within five seconds. Any answer after the pinned handshake proves it;
    /// a handshake that fails or takes too long does not.
    /// </summary>
    private async Task<bool> ProvesAsync(Uri url, CancellationToken stop)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stop);
        timeout.CancelAfter(ServerMoves.ProofTimeout);
        try
        {
            using var response = await _http.GetAsync(new Uri(url, SkakelProtocol.InfoPath), HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            return true;
        }
        catch (Exception ex) when (ex is HttpRequestException || (ex is OperationCanceledException && !stop.IsCancellationRequested))
        {
            LogNotProven(url.Authority, ex.Message);
            return false;
        }
    }

    /// <summary>
    /// Whether a new connection to <paramref name="address"/>, pinned as the link is, presents the
    /// certificate <paramref name="fingerprint"/>. Within five seconds, as a move's proof.
    /// </summary>
    private async Task<bool> PresentsAsync(Uri address, string fingerprint)
    {
        string? presented = null;
        using var handler = Pinning.CreateHandler(() => Pins, p => presented = p);
        using var http = Pinning.CreateClient(handler, ServerMoves.ProofTimeout, disposeHandler: false);
        try
        {
            using var response = await http.GetAsync(new Uri(address, SkakelProtocol.InfoPath), HttpCompletionOption.ResponseHeadersRead);
            return Fingerprints.AreEqual(presented, fingerprint);
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException)
        {
            LogCallFailed(address.Authority, "certificate check", ex);
            return false;
        }
    }

    /// <summary>Waits before the next try. A move ends the wait at once.</summary>
    private async Task PauseAsync(TimeSpan delay, CancellationToken stop)
    {
        Task wake;
        lock (_gate)
        {
            wake = _wake.Task;
        }

        using var pause = CancellationTokenSource.CreateLinkedTokenSource(stop);
        await Task.WhenAny(Task.Delay(delay, _time, pause.Token), wake);
        await pause.CancelAsync();
        stop.ThrowIfCancellationRequested();
        lock (_gate)
        {
            if (_wake.Task.IsCompleted)
            {
                _wake = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            }
        }
    }

    /// <summary>Sets the status and raises it when it changed. Anyone waiting for the hub hears it is not coming.</summary>
    private Task SetStatusAsync(SkakelLinkStatus status)
    {
        lock (_gate)
        {
            if (_status == status)
            {
                return Task.CompletedTask;
            }

            _status = status;
            if (status.State != SkakelLinkState.Connected)
            {
                _ready.TrySetException(new SkakelException(SkakelFailureKind.NotConnected));
                _ = _ready.Task.Exception;
                _ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            }
        }

        return StatusChanged.RaiseAsync(status, _logger);
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Connected to {Server}")]
    private partial void LogConnected(string server);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Connected to {Server} again with a fresh token")]
    private partial void LogRenewed(string server);

    [LoggerMessage(Level = LogLevel.Warning, Message = "The link to {Server} failed: {Failure}")]
    private partial void LogLinkFailed(string server, string failure, Exception exception);

    [LoggerMessage(Level = LogLevel.Warning, Message = "The link to {Server} was lost: {Failure}")]
    private partial void LogLost(string server, string failure);

    [LoggerMessage(Level = LogLevel.Information, Message = "The hub connection to {Server} closed with an error")]
    private partial void LogClosedWithError(string server, Exception exception);

    [LoggerMessage(Level = LogLevel.Warning, Message = "{Server} ended this client: {Failure}. The link stops")]
    private partial void LogEnded(string server, string failure);

    [LoggerMessage(Level = LogLevel.Information, Message = "{Server} is closing the connection: {Reason}")]
    private partial void LogClosing(string server, string reason);

    [LoggerMessage(Level = LogLevel.Information, Message = "{Call} on {Server} failed")]
    private partial void LogCallFailed(string server, string call, Exception exception);

    [LoggerMessage(Level = LogLevel.Information, Message = "{Server} refused a {Type} stream with {Status}: {Detail}")]
    private partial void LogStreamRefused(string type, string server, int status, string detail);

    [LoggerMessage(Level = LogLevel.Information, Message = "The server's certificates changed: pinned {Fingerprint}, next {Next}")]
    private partial void LogPinsChanged(string fingerprint, string next);

    [LoggerMessage(Level = LogLevel.Warning, Message = "The server sent certificates that are not fingerprints; ignored")]
    private partial void LogInvalidCertificates();

    [LoggerMessage(Level = LogLevel.Warning, Message = "The server spoke of its certificate {Fingerprint}, which it does not present; ignored")]
    private partial void LogCertificatesNotPresented(string fingerprint);

    [LoggerMessage(Level = LogLevel.Information, Message = "The server stopped answering at {OldAddress} and was found at {NewAddress}; the link follows it")]
    private partial void LogMoved(string oldAddress, string newAddress);

    [LoggerMessage(Level = LogLevel.Warning, Message = "A server with the pinned fingerprint was heard at {Address}, but it did not prove it holds the certificate: {Reason}")]
    private partial void LogNotProven(string address, string reason);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Could not follow the server to its new address")]
    private partial void LogMoveFailed(Exception exception);

    /// <summary>What one hub connection learned along the way, written by its callbacks.</summary>
    private sealed class Attempt
    {
        private string? _token;
        private string? _closing;
        private string? _presented;
        private long _refreshAt;
        private long _expiresAt;

        public TaskCompletionSource<Exception?> Closed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public string? Token
        {
            get => Volatile.Read(ref _token);
            set => Volatile.Write(ref _token, value);
        }

        public string? Closing
        {
            get => Volatile.Read(ref _closing);
            set => Volatile.Write(ref _closing, value);
        }

        /// <summary>The fingerprint of the certificate this connection's handshakes saw last.</summary>
        public string? Presented
        {
            get => Volatile.Read(ref _presented);
            set => Volatile.Write(ref _presented, value);
        }

        public long RefreshAt
        {
            get => Volatile.Read(ref _refreshAt);
            set => Volatile.Write(ref _refreshAt, value);
        }

        public long ExpiresAt
        {
            get => Volatile.Read(ref _expiresAt);
            set => Volatile.Write(ref _expiresAt, value);
        }
    }

    /// <summary>
    /// Puts the link's token on each request of the app's own HTTP clients, and drops a token the server
    /// refused. Sends only to the link's current address over HTTPS, so the token never goes elsewhere.
    /// </summary>
    private sealed class BearerHandler(SkakelLink link, HttpMessageHandler inner) : DelegatingHandler(inner)
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (!Pinning.IsAt(request.RequestUri, link.Address))
            {
                throw new InvalidOperationException("A link's HTTP client sends only to its server's address, over HTTPS.");
            }

            string? token = null;
            if (request.Headers.Authorization is null)
            {
                token = await link.GetAccessTokenAsync(cancellationToken);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            }

            var response = await base.SendAsync(request, cancellationToken);
            if (token is not null && response.StatusCode == HttpStatusCode.Unauthorized)
            {
                link._tokens.Forget(token);
            }

            return response;
        }
    }
}
