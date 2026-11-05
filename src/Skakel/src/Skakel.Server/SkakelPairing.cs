using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Skakel.Protocol;
using Skakel.Server.Security;

namespace Skakel.Server;

/// <summary>A pairing request as the app's UI sees it. The code and the client's poll token are not in it.</summary>
/// <param name="Id">The request's ID, which approve and deny take.</param>
/// <param name="ClientName">What the client calls itself.</param>
/// <param name="From">The address it asked from.</param>
/// <param name="RequestedAt">When it asked.</param>
/// <param name="ExpiresAt">When the request runs out.</param>
/// <param name="State"><c>waiting</c>, or <c>denied</c> for a short while after three wrong codes, so the UI can say why the request went.</param>
/// <param name="Message">Why it was denied.</param>
public sealed record SkakelPairingRequest(string Id, string ClientName, string From, DateTimeOffset RequestedAt, DateTimeOffset ExpiresAt, string State = PairStates.Waiting, string? Message = null);

/// <summary>What the app's UI shows: the requests, and whether the server stopped taking new ones because its budget of opens is spent.</summary>
/// <param name="Requests">Requests waiting for a person, newest first, and for a moment the ones just denied.</param>
/// <param name="BudgetExhausted">The server takes no new requests until the window moves on.</param>
public sealed record SkakelPairingOverview(IReadOnlyList<SkakelPairingRequest> Requests, bool BudgetExhausted);

/// <summary>What typing a code did.</summary>
public enum SkakelApproval
{
    /// <summary>No such request, or it is no longer waiting for a code.</summary>
    NotWaiting,

    /// <summary>The code was wrong. The third wrong code refuses the request.</summary>
    WrongCode,

    /// <summary>The code matched and the client is registered. It collects its credentials when it next polls.</summary>
    Approved,
}

/// <summary>How a pairing request ended, for the app's log.</summary>
/// <param name="RequestId">The request.</param>
/// <param name="ClientName">What the client calls itself.</param>
/// <param name="From">The address it asked from.</param>
/// <param name="ClientId">The new client, when it was approved.</param>
/// <param name="Refusal">Why it was refused, when it was.</param>
public sealed record SkakelPairingDecision(string RequestId, string ClientName, string From, string? ClientId, string? Refusal);

/// <summary>
/// Pairing requests from clients, kept in memory for a few minutes. A request reaches the UI only
/// after the client revealed its nonce, so the code exists on both ends. A person approves it by typing
/// the code the client shows, through <see cref="ApproveAsync"/>; three wrong codes refuse it.
/// </summary>
/// <remarks>
/// A man in the middle gets a one in a million chance per request, so what bounds it is how many
/// requests the server takes: a budget of opens per window that nothing refunds, split into a small
/// share per address and a ceiling for the whole server, a limit on live requests per address, and a
/// cap on requests a person has to look at. The shares keep one address from spending what everyone
/// else needs; the ceiling stops many addresses grinding. A request that never reveals its nonce is
/// dropped after a few seconds. Each request has its own gate, so approving, refusing and counting
/// wrong codes on one request cannot overlap.
/// </remarks>
public sealed partial class SkakelPairing : IDisposable
{
    internal static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);
    internal static readonly TimeSpan UnrevealedLifetime = TimeSpan.FromSeconds(30);
    internal static readonly TimeSpan DeniedVisibleFor = TimeSpan.FromSeconds(15);
    internal static readonly TimeSpan SweepInterval = TimeSpan.FromSeconds(5);
    internal static readonly TimeSpan OpenWindow = TimeSpan.FromMinutes(5);
    internal const int OpensPerWindow = 60;
    internal const int OpensPerAddressPerWindow = 5;
    internal const int MaxOpen = 10;
    internal const int MaxOpenPerAddress = 3;
    internal const int MaxWrongCodes = 3;
    internal const int MaxClientNameLength = 80;

    private readonly ConcurrentDictionary<string, Request> _requests = new();
    private readonly Queue<(DateTimeOffset At, string Key)> _opens = new();
    private readonly Dictionary<string, int> _opensByAddress = [];
    private readonly Lock _admission = new();
    private readonly ServerState _state;
    private readonly TimeProvider _time;
    private readonly ILogger<SkakelPairing> _logger;
    private readonly ITimer _sweeper;
    private string _pushed = "";
    private int _sweeping;

    internal SkakelPairing(ServerState state, TimeProvider time, ILogger<SkakelPairing> logger)
    {
        _state = state;
        _time = time;
        _logger = logger;
        _sweeper = time.CreateTimer(_ => _ = SweepAsync(), null, SweepInterval, SweepInterval);
    }

    /// <summary>Raised when what the UI shows changed: a request arrived, went, or the budget ran out or came back.</summary>
    public event Func<SkakelPairingOverview, Task>? Changed;

    /// <summary>Raised when a person approved a request, or refused it, or typed the code wrong three times.</summary>
    public event Func<SkakelPairingDecision, Task>? Decided;

    /// <summary>The pending requests with the state of the open budget.</summary>
    public SkakelPairingOverview Overview => new(Pending, BudgetExhausted);

    /// <summary>True while the server-wide ceiling of opens is spent, so every address is turned away until the window moves on.</summary>
    internal bool BudgetExhausted
    {
        get
        {
            lock (_admission)
            {
                ForgetOldOpens(_time.GetUtcNow());
                return _opens.Count >= OpensPerWindow;
            }
        }
    }

    /// <summary>Requests waiting for a person, newest first, and for a moment the ones that were just denied.</summary>
    internal IReadOnlyList<SkakelPairingRequest> Pending
    {
        get
        {
            var now = _time.GetUtcNow();
            return [.. _requests.Values
                .Where(r => IsVisible(r, now))
                .OrderByDescending(r => r.RequestedAt)
                .Select(r => new SkakelPairingRequest(r.Id, r.ClientName, r.From, r.RequestedAt, r.ExpiresAt, r.State, r.State == PairStates.Denied ? r.Message : null))];
        }
    }

    /// <summary>
    /// The person typed a code. A match registers the client and keeps its credentials for it to
    /// collect; a miss counts against the request.
    /// </summary>
    /// <param name="requestId">The request.</param>
    /// <param name="typedCode">The code as typed. Anything but digits is ignored.</param>
    /// <param name="cancellationToken">Cancels the wait and the save.</param>
    public async Task<SkakelApproval> ApproveAsync(string requestId, string? typedCode, CancellationToken cancellationToken = default)
    {
        if (!_requests.TryGetValue(requestId, out var request))
        {
            return SkakelApproval.NotWaiting;
        }

        SkakelApproval result;
        bool changed;
        SkakelPairingDecision? decision = null;
        await request.Gate.WaitAsync(cancellationToken);
        try
        {
            changed = Lapse(request, _time.GetUtcNow());
            if (request.State != PairStates.Waiting || request.Code is null)
            {
                result = SkakelApproval.NotWaiting;
            }
            else if (!PairingCode.IsCode(request.Code, typedCode))
            {
                result = SkakelApproval.WrongCode;
                if (++request.WrongCodes >= MaxWrongCodes)
                {
                    request.State = PairStates.Denied;
                    request.Message = "The code was wrong three times.";
                    request.ShowUntil = _time.GetUtcNow() + DeniedVisibleFor;
                    changed = true;
                    decision = new SkakelPairingDecision(request.Id, request.ClientName, request.From, null, request.Message);
                }
            }
            else
            {
                var client = await _state.RegisterClientAsync(request.ClientName, cancellationToken);
                request.ClientId = client.ClientId;
                request.ClientSecret = client.ClientSecret;
                request.State = PairStates.Approved;
                changed = true;
                result = SkakelApproval.Approved;
                decision = new SkakelPairingDecision(request.Id, request.ClientName, request.From, client.ClientId, null);
            }
        }
        finally
        {
            request.Gate.Release();
        }

        if (changed)
        {
            await RaiseAsync();
        }

        if (decision is not null)
        {
            await Decided.RaiseAsync(decision, _logger);
        }

        return result;
    }

    /// <summary>The person refused the request. False when there is no such request waiting for a code.</summary>
    /// <param name="requestId">The request.</param>
    public async Task<bool> DenyAsync(string requestId)
    {
        if (!_requests.TryGetValue(requestId, out var request))
        {
            return false;
        }

        bool denied;
        await request.Gate.WaitAsync();
        try
        {
            Lapse(request, _time.GetUtcNow());
            denied = request.State == PairStates.Waiting && request.Code is not null;
            if (denied)
            {
                request.State = PairStates.Denied;
            }
        }
        finally
        {
            request.Gate.Release();
        }

        if (denied)
        {
            await RaiseAsync();
            await Decided.RaiseAsync(new SkakelPairingDecision(request.Id, request.ClientName, request.From, null, "Refused on the server."), _logger);
        }

        return denied;
    }

    /// <summary>Stops the sweep timer.</summary>
    public void Dispose() => _sweeper.Dispose();

    /// <summary>
    /// Step 1: a client commits to its nonce. Returns the request ID, the server's nonce and the poll
    /// token the client must present from now on, or null when the server takes no more requests.
    /// </summary>
    internal PairOpened? Open(string clientName, string commitment, IPAddress? from)
    {
        var now = _time.GetUtcNow();
        var key = AddressKey(from);
        lock (_admission)
        {
            ForgetOldOpens(now);
            if (_opens.Count >= OpensPerWindow
                || _opensByAddress.GetValueOrDefault(key) >= OpensPerAddressPerWindow
                || _requests.Values.Count(r => IsRevealedAndWaiting(r, now)) >= MaxOpen
                || _requests.Values.Count(r => r.AddressKey == key && IsLive(r, now)) >= MaxOpenPerAddress)
            {
                return null;
            }

            _opens.Enqueue((now, key));
            _opensByAddress[key] = _opensByAddress.GetValueOrDefault(key) + 1;

            // The ID is the client's handle on its request; the poll token is the proof that it is the one asking. Both are unguessable.
            var request = new Request(
                Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16)),
                clientName,
                Display(from),
                key,
                commitment,
                PairingCode.NewNonce(),
                Secrets.NewToken(),
                now,
                now + Lifetime);
            _requests[request.Id] = request;
            return new PairOpened(request.Id, request.ServerNonce, request.ExpiresAt, request.PollToken);
        }
    }

    /// <summary>Step 2: the client reveals its nonce. Only now is there a code, and the UI shows the request.</summary>
    internal async Task<bool> RevealAsync(string id, string clientNonce)
    {
        if (!_requests.TryGetValue(id, out var request))
        {
            return false;
        }

        bool revealed;
        await request.Gate.WaitAsync();
        try
        {
            var now = _time.GetUtcNow();
            revealed = request.State == PairStates.Waiting && request.Code is null && !IsStale(request, now) && request.ExpiresAt > now
                && PairingCode.Matches(request.Commitment, clientNonce);
            if (revealed)
            {
                request.Code = PairingCode.Compute(_state.Fingerprint, clientNonce, request.ServerNonce);
            }
        }
        finally
        {
            request.Gate.Release();
        }

        if (revealed)
        {
            await RaiseAsync();
        }

        return revealed;
    }

    /// <summary>The client gave up. Only the client holding the poll token can, and only for a request still waiting.</summary>
    internal async Task<bool> WithdrawAsync(string id, string? pollToken)
    {
        if (!_requests.TryGetValue(id, out var request) || !Secrets.SameToken(request.PollToken, pollToken))
        {
            return false;
        }

        bool withdrawn;
        bool wasVisible;
        await request.Gate.WaitAsync();
        try
        {
            Lapse(request, _time.GetUtcNow());
            withdrawn = request.State == PairStates.Waiting && _requests.TryRemove(id, out _);
            wasVisible = withdrawn && request.Code is not null;
        }
        finally
        {
            request.Gate.Release();
        }

        if (wasVisible)
        {
            await RaiseAsync();
        }

        return withdrawn;
    }

    /// <summary>The client polls. Credentials are handed over once, then the request is gone. Null for an unknown request or a wrong token.</summary>
    internal async Task<PairPoll?> PollAsync(string id, string? pollToken)
    {
        if (!_requests.TryGetValue(id, out var request) || !Secrets.SameToken(request.PollToken, pollToken))
        {
            return null;
        }

        PairPoll poll;
        bool changed;
        await request.Gate.WaitAsync();
        try
        {
            changed = Lapse(request, _time.GetUtcNow());
            if (request.State == PairStates.Approved)
            {
                _requests.TryRemove(id, out _);
                poll = new PairPoll(PairStates.Approved, request.ClientId, request.ClientSecret);
            }
            else
            {
                poll = new PairPoll(request.State);
            }
        }
        finally
        {
            request.Gate.Release();
        }

        if (changed)
        {
            await RaiseAsync();
        }

        return poll;
    }

    /// <summary>The address a limit counts: one IPv4 address, or one IPv6 /64, which is what a single network hands a host.</summary>
    internal static string AddressKey(IPAddress? address)
    {
        if (address is null)
        {
            return "unknown";
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        return address.AddressFamily == AddressFamily.InterNetworkV6
            ? $"{Convert.ToHexString(address.GetAddressBytes().AsSpan(0, 8))}/64"
            : address.ToString();
    }

    /// <summary>Drops opens older than the window, with the admission lock held. The per-address counts never hold more keys than the queue holds opens.</summary>
    private void ForgetOldOpens(DateTimeOffset now)
    {
        while (_opens.Count > 0 && _opens.Peek().At + OpenWindow <= now)
        {
            var (_, key) = _opens.Dequeue();
            if (_opensByAddress[key] <= 1)
            {
                _opensByAddress.Remove(key);
            }
            else
            {
                _opensByAddress[key]--;
            }
        }
    }

    private static string Display(IPAddress? address) =>
        address is null ? "unknown" : (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address).ToString();

    /// <summary>A request whose client never revealed its nonce in time. It is as good as gone.</summary>
    private static bool IsStale(Request request, DateTimeOffset now) =>
        request.State == PairStates.Waiting && request.Code is null && request.RequestedAt + UnrevealedLifetime <= now;

    private static bool IsLive(Request request, DateTimeOffset now) =>
        request.State == PairStates.Waiting && request.ExpiresAt > now && !IsStale(request, now);

    private static bool IsRevealedAndWaiting(Request request, DateTimeOffset now) =>
        request.State == PairStates.Waiting && request.Code is not null && request.ExpiresAt > now;

    private static bool IsVisible(Request request, DateTimeOffset now) =>
        IsRevealedAndWaiting(request, now) || (request.State == PairStates.Denied && request.ShowUntil > now);

    /// <summary>Moves a waiting request past its lifetime to expired, with its gate held. True when the UI list changes with it.</summary>
    private static bool Lapse(Request request, DateTimeOffset now)
    {
        if (request.State != PairStates.Waiting || request.ExpiresAt > now)
        {
            return false;
        }

        request.State = PairStates.Expired;
        return request.Code is not null;
    }

    /// <summary>Expires requests, drops dead ones and pushes the list when what the UI shows changed, even if nobody called in.</summary>
    private async Task SweepAsync()
    {
        if (Interlocked.Exchange(ref _sweeping, 1) == 1)
        {
            return;
        }

        try
        {
            var now = _time.GetUtcNow();
            foreach (var request in _requests.Values)
            {
                await request.Gate.WaitAsync();
                try
                {
                    Lapse(request, now);
                    if (IsStale(request, now) || request.ExpiresAt + Lifetime <= now)
                    {
                        _requests.TryRemove(request.Id, out _);
                    }
                }
                finally
                {
                    request.Gate.Release();
                }
            }

            if (Signature(Overview) != Volatile.Read(ref _pushed))
            {
                await RaiseAsync();
            }
        }
        catch (Exception ex)
        {
            LogSweepFailed(ex);
        }
        finally
        {
            Volatile.Write(ref _sweeping, 0);
        }
    }

    private static string Signature(SkakelPairingOverview overview) =>
        $"{overview.BudgetExhausted}|{string.Join('|', overview.Requests.Select(v => $"{v.Id}:{v.State}"))}";

    private Task RaiseAsync()
    {
        var overview = Overview;
        Volatile.Write(ref _pushed, Signature(overview));
        return Changed.RaiseAsync(overview, _logger);
    }

    [LoggerMessage(Level = LogLevel.Error, Message = "Sweeping pairing requests failed")]
    private partial void LogSweepFailed(Exception exception);

    private sealed class Request(string id, string clientName, string from, string addressKey, string commitment, string serverNonce, string pollToken, DateTimeOffset requestedAt, DateTimeOffset expiresAt)
    {
        public string Id { get; } = id;
        public string ClientName { get; } = clientName;
        public string From { get; } = from;
        public string AddressKey { get; } = addressKey;
        public string Commitment { get; } = commitment;
        public string ServerNonce { get; } = serverNonce;
        public string PollToken { get; } = pollToken;
        public DateTimeOffset RequestedAt { get; } = requestedAt;
        public DateTimeOffset ExpiresAt { get; } = expiresAt;

        /// <summary>Held while a state change on this request runs.</summary>
        public SemaphoreSlim Gate { get; } = new(1, 1);

        public string? Code { get; set; }
        public string State { get; set; } = PairStates.Waiting;
        public int WrongCodes { get; set; }
        public string? Message { get; set; }
        public DateTimeOffset? ShowUntil { get; set; }
        public string? ClientId { get; set; }
        public string? ClientSecret { get; set; }
    }
}
