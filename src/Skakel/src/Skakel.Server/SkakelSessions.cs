using System.Collections.Concurrent;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Skakel.Protocol;

namespace Skakel.Server;

/// <summary>
/// The live hub connections and streams of the clients. When a client is revoked or its secret is
/// rotated, its connections are told why (<c>SkakelClosing</c>) and then all of them end at once, its
/// streams with a close code, so a revoke ends what the client is doing now and not only what it asks
/// for next. When the server stops, every connection and stream ends the same way. The hub
/// connections also hear of every change to the certificates.
/// </summary>
public sealed partial class SkakelSessions : IHostedService
{
    /// <summary>How long telling a hub connection why it ends may take before it is ended anyway.</summary>
    internal static readonly TimeSpan SendTimeout = TimeSpan.FromSeconds(2);

    private readonly ConcurrentDictionary<long, Session> _sessions = new();
    /// <summary>How long the host's stopping waits for the connections to be told and the streams closed.</summary>
    internal static readonly TimeSpan StopWait = TimeSpan.FromSeconds(3);

    private readonly ServerState _state;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly ILogger<SkakelSessions> _logger;
    private SkakelCertificates? _certificates;
    private CancellationTokenRegistration _onStopping;
    private long _next;
    private volatile bool _stopping;

    internal SkakelSessions(ServerState state, IHostApplicationLifetime lifetime, ILogger<SkakelSessions> logger)
    {
        _state = state;
        _lifetime = lifetime;
        _logger = logger;
    }

    /// <summary>
    /// Ends every hub connection and stream: the hub connections hear <c>SkakelClosing</c> with
    /// <c>stopping</c>, and the streams close with 4003. For an app that stops serving Skakel clients
    /// without stopping the host. New ones are still let in afterwards.
    /// </summary>
    public Task EndAllAsync() => Task.WhenAll(_sessions.Values.Select(s => EndAsync(s, SkakelClosingReasons.Stopping)));

    Task IHostedService.StartAsync(CancellationToken cancellationToken)
    {
        _certificates = _state.Certificates;
        _state.Changed += OnStateChangedAsync;
        _onStopping = _lifetime.ApplicationStopping.Register(OnStopping);
        return Task.CompletedTask;
    }

    async Task IHostedService.StopAsync(CancellationToken cancellationToken)
    {
        _stopping = true;
        _state.Changed -= OnStateChangedAsync;
        await _onStopping.DisposeAsync();
        await EndAllAsync();
    }

    /// <summary>
    /// When the host starts stopping, before SignalR closes its connections: the stopping callbacks run
    /// newest first, and this one was registered after the hub was mapped. Waits a little, so the
    /// connections are told before they go.
    /// </summary>
    private void OnStopping()
    {
        _stopping = true;
        try
        {
            EndAllAsync().Wait(StopWait);
        }
        catch (AggregateException ex)
        {
            LogEndFailed("*", ex);
        }
    }

    /// <summary>Tracks a hub connection until the returned handle is disposed.</summary>
    internal IDisposable AddHub(string clientId, int generation, IClientProxy caller, Action abort) =>
        Add(new Session(clientId, generation, caller, async reason =>
        {
            try
            {
                await caller.SendAsync(SkakelHubMethods.Closing, new SkakelClosing(reason)).WaitAsync(SendTimeout);
            }
            catch (Exception ex)
            {
                LogNotTold(clientId, ex.Message);
            }

            abort();
        }));

    /// <summary>Tracks a stream until the returned handle is disposed. <paramref name="end"/> closes it with the code for the reason.</summary>
    internal IDisposable AddStream(string clientId, int generation, Func<string, Task> end) =>
        Add(new Session(clientId, generation, null, end));

    /// <summary>
    /// Tracks a session. One whose client is already out of date, or that arrives while the server stops,
    /// is ended at once, which closes the gap between the check that let it in and this call.
    /// </summary>
    private Handle Add(Session session)
    {
        var id = Interlocked.Increment(ref _next);
        _sessions[id] = session;
        if (_stopping)
        {
            _ = EndAsync(session, SkakelClosingReasons.Stopping);
        }
        else if (!_state.IsCurrent(session.ClientId, session.Generation))
        {
            _ = EndAsync(session, ReasonFor(session));
        }

        return new Handle(() => _sessions.TryRemove(id, out _));
    }

    private async Task OnStateChangedAsync(StateChange _)
    {
        var stale = _sessions.Values.Where(s => !_state.IsCurrent(s.ClientId, s.Generation)).ToList();
        await Task.WhenAll(stale.Select(s => EndAsync(s, ReasonFor(s))));

        var certificates = _state.Certificates;
        if (certificates != Interlocked.Exchange(ref _certificates, certificates))
        {
            await Task.WhenAll(_sessions.Values
                .Where(s => s.Hub is not null && _state.IsCurrent(s.ClientId, s.Generation))
                .Select(s => SendCertificatesAsync(s, certificates)));
        }
    }

    private async Task SendCertificatesAsync(Session session, SkakelCertificates certificates)
    {
        try
        {
            await session.Hub!.SendAsync(SkakelHubMethods.Certificates, certificates).WaitAsync(SendTimeout);
        }
        catch (Exception ex)
        {
            LogNotTold(session.ClientId, ex.Message);
        }
    }

    /// <summary>Revoked when the client is gone, rotated when it is there at another generation.</summary>
    private string ReasonFor(Session session) =>
        _state.Find(session.ClientId) is null ? SkakelClosingReasons.Revoked : SkakelClosingReasons.Rotated;

    private async Task EndAsync(Session session, string reason)
    {
        if (!session.BeginEnd())
        {
            return;
        }

        LogEnding(session.ClientId, reason);
        try
        {
            await session.End(reason);
        }
        catch (Exception ex)
        {
            LogEndFailed(session.ClientId, ex);
        }
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Ending a connection of client {ClientId}: {Reason}")]
    private partial void LogEnding(string clientId, string reason);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Could not tell a hub connection of client {ClientId}: {Reason}")]
    private partial void LogNotTold(string clientId, string reason);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Ending a connection of client {ClientId} failed")]
    private partial void LogEndFailed(string clientId, Exception exception);

    private sealed class Session(string clientId, int generation, IClientProxy? hub, Func<string, Task> end)
    {
        private int _ending;

        public string ClientId { get; } = clientId;

        public int Generation { get; } = generation;

        /// <summary>The hub connection, or null for a stream.</summary>
        public IClientProxy? Hub { get; } = hub;

        public Func<string, Task> End { get; } = end;

        /// <summary>True the first time only, so a session is ended once.</summary>
        public bool BeginEnd() => Interlocked.Exchange(ref _ending, 1) == 0;
    }

    private sealed class Handle(Action release) : IDisposable
    {
        public void Dispose() => release();
    }
}
