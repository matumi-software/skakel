using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.Logging;
using Skakel.Protocol;

namespace Skakel.Client;

/// <summary>
/// Pairs with a server, so the client gets its credentials without anyone typing a secret. Opens a
/// request over HTTPS pinned to the fingerprint discovery announced, with a commitment to a nonce,
/// reveals the nonce, and gives the six-digit <see cref="Code"/> to show. A person types it on the
/// server; <see cref="WaitAsync"/> polls until they did and hands the credentials to the app, which
/// decides where to keep them. Disposing a request that is still waiting withdraws it.
/// </summary>
/// <example><code>
/// await using var pairing = await SkakelPairingClient.OpenAsync(server.Url, server.Fingerprint, Environment.MachineName);
/// Show(pairing.Code);
/// var credentials = await pairing.WaitAsync(cancellationToken);
/// </code></example>
public sealed partial class SkakelPairingClient : IAsyncDisposable
{
    /// <summary>How often a waiting request is polled. The server allows once a second.</summary>
    internal static TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(2);

    /// <summary>How long past its expiry a request is still polled, for a clock that differs from the server's.</summary>
    private static readonly TimeSpan ExpiryGrace = TimeSpan.FromSeconds(30);

    private readonly HttpClient _http;
    private readonly ILogger _logger;
    private readonly TimeProvider _time;
    private readonly string _requestId;
    private readonly string _pollToken;
    private int _done;

    private SkakelPairingClient(HttpClient http, Uri server, SkakelPins pins, string serverName, PairOpened opened, string code, ILogger logger, TimeProvider time)
    {
        _http = http;
        _logger = logger;
        _time = time;
        _requestId = opened.RequestId;
        _pollToken = opened.PollToken;
        Address = server;
        Pins = pins;
        ServerName = serverName;
        Code = code;
        ExpiresAt = opened.ExpiresAt;
    }

    /// <summary>The server's address.</summary>
    public Uri Address { get; }

    /// <summary>The pinned certificate. The app keeps it with the credentials.</summary>
    public SkakelPins Pins { get; }

    /// <summary>The server's name, from its info.</summary>
    public string ServerName { get; }

    /// <summary>The six-digit code to show. The person types it on the server.</summary>
    public string Code { get; }

    /// <summary>When the request runs out on the server.</summary>
    public DateTimeOffset ExpiresAt { get; }

    /// <summary>
    /// Opens a pairing request: checks the server speaks this client's protocol, sends the commitment,
    /// reveals the nonce, and works out the code.
    /// </summary>
    /// <param name="address">The server's HTTPS address, from discovery.</param>
    /// <param name="fingerprint">The certificate's fingerprint, from discovery. It is pinned from here on, and goes into the code.</param>
    /// <param name="clientName">What the server's people see this client as: 1 to 80 characters, such as the machine's name.</param>
    /// <param name="options">Logging, time and the request timeout.</param>
    /// <param name="cancellationToken">Cancels opening.</param>
    /// <exception cref="SkakelException">The server could not be reached, presented another certificate, speaks no common version, or refused the request.</exception>
    public static async Task<SkakelPairingClient> OpenAsync(Uri address, string fingerprint, string clientName, SkakelClientOptions? options = null, CancellationToken cancellationToken = default)
    {
        var server = Pinning.BaseAddress(address, nameof(address));
        var pins = new SkakelPins(fingerprint);
        var name = clientName?.Trim();
        if (string.IsNullOrEmpty(name) || name.Length > 80)
        {
            throw new ArgumentException("Give the client a name of 1 to 80 characters.", nameof(clientName));
        }

        options ??= new SkakelClientOptions();
        var logger = options.Loggers.CreateLogger<SkakelPairingClient>();
        var handler = Pinning.CreateHandler(() => pins);
        var http = new HttpClient(handler) { BaseAddress = server, Timeout = options.RequestTimeout };
        try
        {
            var info = await SkakelInfoClient.ReadAsync(http, server, logger, cancellationToken);
            SkakelVersions.Require(info.Versions);

            var nonce = PairingCode.NewNonce();
            using var open = await http.PostAsJsonAsync(SkakelProtocol.PairPath, new PairOpenRequest(name, PairingCode.Commit(nonce)), SkakelJson.Options, cancellationToken);
            open.EnsureSuccessStatusCode();
            var opened = await open.Content.ReadFromJsonAsync<PairOpened>(SkakelJson.Options, cancellationToken);
            if (opened is not { RequestId.Length: > 0, ServerNonce.Length: > 0, PollToken.Length: > 0 })
            {
                throw new InvalidDataException("The pairing answer is missing the request, the nonce or the poll token.");
            }

            var pairing = new SkakelPairingClient(http, server, pins, info.Name, opened, PairingCode.Compute(pins.Fingerprint, nonce, opened.ServerNonce), logger, options.Time);
            try
            {
                using var revealed = await http.PostAsJsonAsync($"{SkakelProtocol.PairPath}/{Uri.EscapeDataString(opened.RequestId)}/reveal", new PairRevealRequest(nonce), SkakelJson.Options, cancellationToken);
                if (revealed.StatusCode == HttpStatusCode.NotFound)
                {
                    // Dropped: it took too long to reveal, or the server restarted.
                    throw new SkakelException(SkakelFailureKind.PairingExpired);
                }

                revealed.EnsureSuccessStatusCode();
            }
            catch
            {
                await pairing.DisposeAsync();
                throw;
            }

            LogWaiting(logger, info.Name);
            return pairing;
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            http.Dispose();
            if (ex is not SkakelException { InnerException: null })
            {
                LogFailed(logger, server.Authority, ex);
            }

            throw Failures.Exception(ex);
        }
        catch
        {
            http.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Polls until the person typed the code on the server, and returns the credentials. They are handed
    /// over once: keep them before anything else.
    /// </summary>
    /// <param name="cancellationToken">Stops waiting. The request stays open until it is withdrawn or disposed.</param>
    /// <exception cref="SkakelException">The server refused the request (<see cref="SkakelFailureKind.PairingDenied"/>), it ran out (<see cref="SkakelFailureKind.PairingExpired"/>), or the server could not be reached.</exception>
    public async Task<SkakelCredentials> WaitAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _done) == 2, this);
        if (Volatile.Read(ref _done) != 0)
        {
            throw new InvalidOperationException("This pairing request is finished.");
        }

        try
        {
            while (true)
            {
                if (_time.GetUtcNow() > ExpiresAt + ExpiryGrace)
                {
                    throw new SkakelException(SkakelFailureKind.PairingExpired);
                }

                await Task.Delay(PollInterval, _time, cancellationToken);
                using var request = new HttpRequestMessage(HttpMethod.Get, $"{SkakelProtocol.PairPath}/{Uri.EscapeDataString(_requestId)}");
                request.Headers.Add(SkakelProtocol.PairTokenHeader, _pollToken);
                using var response = await _http.SendAsync(request, cancellationToken);
                if (response.StatusCode == HttpStatusCode.TooManyRequests)
                {
                    // Others from this address are pairing too; the next poll is soon enough.
                    continue;
                }

                if (response.StatusCode == HttpStatusCode.NotFound)
                {
                    Finish();
                    throw new SkakelException(SkakelFailureKind.PairingExpired);
                }

                response.EnsureSuccessStatusCode();
                var poll = await response.Content.ReadFromJsonAsync<PairPoll>(SkakelJson.Options, cancellationToken);
                switch (poll?.State)
                {
                    case PairStates.Waiting:
                        continue;
                    case PairStates.Approved when !string.IsNullOrWhiteSpace(poll.ClientId) && !string.IsNullOrEmpty(poll.ClientSecret):
                        Finish();
                        LogPaired(_logger, ServerName);
                        return new SkakelCredentials(poll.ClientId, poll.ClientSecret);
                    case PairStates.Denied:
                        Finish();
                        throw new SkakelException(SkakelFailureKind.PairingDenied);
                    case PairStates.Expired:
                        Finish();
                        throw new SkakelException(SkakelFailureKind.PairingExpired);
                    default:
                        throw new InvalidDataException($"The poll answered the state '{poll?.State}'.");
                }
            }
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            if (ex is not SkakelException { InnerException: null })
            {
                LogFailed(_logger, Address.Authority, ex);
            }

            throw Failures.Exception(ex);
        }
    }

    /// <summary>Withdraws the request, when it is still waiting, so it does not sit on the server's list until it expires. Never throws.</summary>
    public async Task WithdrawAsync()
    {
        if (Interlocked.CompareExchange(ref _done, 1, 0) != 0)
        {
            return;
        }

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Delete, $"{SkakelProtocol.PairPath}/{Uri.EscapeDataString(_requestId)}");
            request.Headers.Add(SkakelProtocol.PairTokenHeader, _pollToken);
            using var withdrawn = await _http.SendAsync(request, CancellationToken.None);
            LogWithdrawn(_logger, ServerName, (int)withdrawn.StatusCode);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            // The server expires it on its own.
            LogFailed(_logger, Address.Authority, ex);
        }
    }

    /// <summary>Withdraws the request if it is still waiting, and lets go of the connection.</summary>
    public async ValueTask DisposeAsync()
    {
        await WithdrawAsync();
        Volatile.Write(ref _done, 2);
        _http.Dispose();
    }

    /// <summary>The request is over on the server; there is nothing to withdraw.</summary>
    private void Finish() => Interlocked.CompareExchange(ref _done, 1, 0);

    [LoggerMessage(Level = LogLevel.Information, Message = "Waiting for the code to be typed on {Server}")]
    private static partial void LogWaiting(ILogger logger, string server);

    [LoggerMessage(Level = LogLevel.Information, Message = "Paired with {Server}")]
    private static partial void LogPaired(ILogger logger, string server);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Withdrew the pairing request on {Server}: {Status}")]
    private static partial void LogWithdrawn(ILogger logger, string server, int status);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Pairing with {Server} failed")]
    private static partial void LogFailed(ILogger logger, string server, Exception exception);
}
