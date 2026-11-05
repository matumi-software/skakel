using System.Collections.Concurrent;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using Skakel.Protocol;
using Skakel.Server.Security;

namespace Skakel.Server;

/// <summary>A change to the state: what it was and what it is now.</summary>
internal sealed record StateChange(SkakelState Previous, SkakelState Next);

/// <summary>
/// Owns the <see cref="SkakelState"/>: the registered clients, the token signing keys and the
/// certificates. Loads it at start and makes a key and a certificate the first time. Every change is
/// saved through the app's <see cref="ISkakelStore"/> first, then applied, then announced.
/// </summary>
/// <remarks>
/// Both the signing key and the certificate can be rotated. A new signing key signs from then on, and
/// the one it replaced is still accepted until every token it signed has expired
/// (<see cref="RetiredKeyMargin"/> past the token lifetime), then dropped. A new certificate is
/// prepared first and kept beside the current one, so paired clients can learn its fingerprint over the
/// hub they already trust, and the switch presents it.
/// </remarks>
internal sealed partial class ServerState : IHostedService, IDisposable
{
    /// <summary>How long past the token lifetime a replaced key is still accepted, for a token issued while the rotation was applied.</summary>
    internal static readonly TimeSpan RetiredKeyMargin = TimeSpan.FromMinutes(5);

    private readonly ISkakelStore _store;
    private readonly SkakelServerOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger<ServerState> _logger;
    private readonly SemaphoreSlim _write = new(1, 1);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastSeen = new();
    private readonly Lock _applying = new();
    private readonly Dictionary<string, RsaSecurityKey> _rsaKeys = [];
    private readonly List<X509Certificate2> _replaced = [];
    private readonly ITimer _prune;
    private SkakelState? _current;
    private SigningKeys? _keys;
    private string? _keysSource;
    private CancellationTokenSource _keysChanged = new();
    private X509Certificate2? _certificate;
    private string? _certificatePfx;
    private string? _nextPfx;
    private string? _nextFingerprint;
    private IReadOnlyList<SkakelClientView>? _raisedClients;
    private SkakelKeysView? _raisedKeys;

    public ServerState(ISkakelStore store, IOptions<SkakelServerOptions> options, TimeProvider time, ILogger<ServerState> logger)
    {
        _store = store;
        _options = options.Value;
        _time = time;
        _logger = logger;
        _prune = time.CreateTimer(_ => _ = PruneRetiredKeysAsync(), null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
    }

    /// <summary>Raised after a change was saved and applied.</summary>
    public event Func<StateChange, Task>? Changed;

    /// <summary>Raised after what the UI shows of the clients changed.</summary>
    public event Func<IReadOnlyList<SkakelClientView>, Task>? ClientsChanged;

    /// <summary>Raised after the certificates or the signing key changed.</summary>
    public event Func<SkakelKeysView, Task>? KeysChanged;

    public SkakelState Current => Volatile.Read(ref _current) ?? throw NotLoaded();

    public SecurityKey SigningKey => Keys.Signing;

    /// <summary>The signing key first, then the retired keys whose tokens may still be live.</summary>
    public IReadOnlyList<SecurityKey> ValidationKeys => Keys.Validation;

    /// <summary>Fires when the keys change, so the token server and the validation build their options again.</summary>
    public IChangeToken GetChangeToken() => new CancellationChangeToken(Volatile.Read(ref _keysChanged).Token);

    /// <summary>The certificate this server presents. After a switch it is the new one, at once, for every new connection.</summary>
    public X509Certificate2 Certificate => Volatile.Read(ref _certificate) ?? throw NotLoaded();

    public string Fingerprint => Fingerprints.Of(Certificate);

    /// <summary>The prepared next certificate's fingerprint, or null when none is prepared.</summary>
    public string? NextFingerprint => Volatile.Read(ref _nextFingerprint);

    public SkakelCertificates Certificates => new(Fingerprint, NextFingerprint);

    public SkakelKeysView KeysView
    {
        get
        {
            var state = Current;
            return new SkakelKeysView(
                Fingerprint,
                NextFingerprint,
                state.NextCertificate?.PreparedAt,
                state.SigningKey.KeyId,
                state.SigningKey.CreatedAt,
                state.RetiredSigningKeys.Count > 0 ? state.RetiredSigningKeys.Max(r => r.AcceptUntil) : null);
        }
    }

    public IReadOnlyList<SkakelClientView> Clients => ToViews(Current);

    private SigningKeys Keys => Volatile.Read(ref _keys) ?? throw NotLoaded();

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var now = _time.GetUtcNow();
        var state = await _store.LoadAsync(cancellationToken);
        if (state is null)
        {
            state = new SkakelState
            {
                Clients = [],
                SigningKey = NewSigningKey(now),
                CertificatePfx = NewCertificate(now),
            };
            await _store.SaveAsync(state, cancellationToken);
        }
        else if (state.RetiredSigningKeys.Any(r => r.AcceptUntil <= now))
        {
            state = state with { RetiredSigningKeys = Unexpired(state.RetiredSigningKeys, now) };
            await _store.SaveAsync(state, cancellationToken);
        }

        Volatile.Write(ref _current, state);
        Apply(state);
        _raisedClients = Clients;
        _raisedKeys = KeysView;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _prune.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
        return Task.CompletedTask;
    }

    /// <summary>
    /// Applies <paramref name="change"/> to the state, one change at a time: saves the result, applies it,
    /// then raises <see cref="Changed"/>. A change that returns the state it was given saves nothing.
    /// </summary>
    public async Task<SkakelState> UpdateAsync(Func<SkakelState, SkakelState> change, CancellationToken cancellationToken)
    {
        SkakelState previous;
        SkakelState next;
        await _write.WaitAsync(cancellationToken);
        try
        {
            previous = Current;
            next = change(previous);
            if (ReferenceEquals(next, previous))
            {
                return previous;
            }

            await _store.SaveAsync(next, cancellationToken);
            Volatile.Write(ref _current, next);
            Apply(next);
        }
        finally
        {
            _write.Release();
        }

        await Changed.RaiseAsync(new StateChange(previous, next), _logger);
        await RaiseViewsAsync();
        return next;
    }

    public async Task<SkakelNewClient> RegisterClientAsync(string name, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var secret = Secrets.NewSecret();
        var client = new SkakelClientRecord(Secrets.NewId("client"), name.Trim(), Secrets.Hash(secret), _time.GetUtcNow(), 1, _options.KeepClientSecrets ? secret : null);
        await UpdateAsync(current => current with { Clients = [.. current.Clients, client] }, cancellationToken);
        return new SkakelNewClient(client.Id, client.Name, secret);
    }

    /// <summary>
    /// Replaces the secret and raises the generation, so every token issued before stops being accepted.
    /// Null when there is no such client.
    /// </summary>
    public async Task<string?> RotateSecretAsync(string clientId, CancellationToken cancellationToken)
    {
        var secret = Secrets.NewSecret();
        var found = false;
        await UpdateAsync(current =>
        {
            found = current.Clients.Any(c => c.Id == clientId);
            return found
                ? current with
                {
                    Clients = [.. current.Clients.Select(c => c.Id == clientId
                        ? c with { SecretHash = Secrets.Hash(secret), Secret = _options.KeepClientSecrets ? secret : null, Generation = c.Generation + 1 }
                        : c)],
                }
                : current;
        }, cancellationToken);
        return found ? secret : null;
    }

    /// <summary>Removes a client. False when there is no such client.</summary>
    public async Task<bool> RevokeClientAsync(string clientId, CancellationToken cancellationToken)
    {
        var found = false;
        await UpdateAsync(current =>
        {
            found = current.Clients.Any(c => c.Id == clientId);
            return found
                ? current with
                {
                    Clients = [.. current.Clients.Where(c => c.Id != clientId)],
                    NextCertificate = current.NextCertificate is { } next ? next with { ReceivedBy = [.. next.ReceivedBy.Where(id => id != clientId)] } : null,
                }
                : current;
        }, cancellationToken);
        _lastSeen.TryRemove(clientId, out _);
        return found;
    }

    public SkakelClientRecord? Find(string? clientId) => clientId is null ? null : Current.Clients.FirstOrDefault(c => c.Id == clientId);

    /// <summary>The client is registered and its secret has not been rotated since the token was issued.</summary>
    public bool IsCurrent(string? clientId, int? generation) =>
        generation is not null && Find(clientId)?.Generation == generation;

    /// <summary>Whether a validated bearer token belongs to a registered client at its current generation.</summary>
    public bool IsCurrent(ClaimsPrincipal? principal) =>
        principal is not null && IsCurrent(principal.GetSkakelClientId(), principal.GetSkakelGeneration());

    /// <summary>
    /// The generation the secret was verified against, or null when the client is unknown or the secret
    /// is wrong. The token is issued for exactly this generation, so a secret rotated in between never
    /// yields a token for the newer one.
    /// </summary>
    public int? Validate(string clientId, string clientSecret)
    {
        var client = Find(clientId);
        if (client is null || !Secrets.Verify(clientSecret, client.SecretHash))
        {
            return null;
        }

        _lastSeen[clientId] = _time.GetUtcNow();
        return client.Generation;
    }

    /// <summary>Makes a new signing key and signs with it from now on. Returns its key id.</summary>
    public async Task<string> RotateSigningKeyAsync(CancellationToken cancellationToken)
    {
        var now = _time.GetUtcNow();
        var key = NewSigningKey(now);
        await UpdateAsync(current => current with
        {
            SigningKey = key,
            RetiredSigningKeys =
            [
                .. Unexpired(current.RetiredSigningKeys, now),
                current.SigningKey with { AcceptUntil = now + SkakelProtocol.AccessTokenLifetime + RetiredKeyMargin },
            ],
        }, cancellationToken);
        return key.KeyId;
    }

    /// <summary>Makes the next certificate and keeps it beside the current one. Its fingerprint, or null when one is already prepared.</summary>
    public async Task<string?> PrepareCertificateAsync(CancellationToken cancellationToken)
    {
        if (Current.NextCertificate is not null)
        {
            return null;
        }

        var now = _time.GetUtcNow();
        var pfx = NewCertificate(now);
        var written = await UpdateAsync(current => current.NextCertificate is null
            ? current with { NextCertificate = new SkakelNextCertificateRecord(pfx, now, []) }
            : current, cancellationToken);
        return written.NextCertificate?.Pfx == pfx ? NextFingerprint : null;
    }

    /// <summary>Drops the prepared certificate. False when none was prepared.</summary>
    public async Task<bool> CancelCertificateAsync(CancellationToken cancellationToken)
    {
        var dropped = false;
        await UpdateAsync(current =>
        {
            dropped = current.NextCertificate is not null;
            return dropped ? current with { NextCertificate = null } : current;
        }, cancellationToken);
        return dropped;
    }

    /// <summary>Presents the prepared certificate from now on. What changed, or null when none was prepared.</summary>
    public async Task<SkakelCertificateSwitch?> SwitchCertificateAsync(CancellationToken cancellationToken)
    {
        var from = Fingerprint;
        SkakelNextCertificateRecord? next = null;
        IReadOnlyList<SkakelClientRecord> clients = [];
        await UpdateAsync(current =>
        {
            next = current.NextCertificate;
            clients = current.Clients;
            return next is null ? current : current with { CertificatePfx = next.Pfx, NextCertificate = null };
        }, cancellationToken);

        return next is not { } switched
            ? null
            : new SkakelCertificateSwitch(from, Fingerprint, [.. clients.Where(c => !switched.ReceivedBy.Contains(c.Id)).Select(c => c.Name)]);
    }

    /// <summary>
    /// Records that a client stored the next certificate's fingerprint. Ignored unless it is the prepared
    /// one and the client is registered.
    /// </summary>
    public async Task MarkNextCertificateReceivedAsync(string clientId, string fingerprint, CancellationToken cancellationToken)
    {
        var next = Current.NextCertificate;
        if (next is null || next.ReceivedBy.Contains(clientId) || Find(clientId) is null || !Fingerprints.AreEqual(fingerprint, NextFingerprint))
        {
            return;
        }

        await UpdateAsync(current => current.NextCertificate is { } n && n.Pfx == next.Pfx && !n.ReceivedBy.Contains(clientId) && current.Clients.Any(c => c.Id == clientId)
            ? current with { NextCertificate = n with { ReceivedBy = [.. n.ReceivedBy, clientId] } }
            : current, cancellationToken);
    }

    public IReadOnlyList<SkakelClientView> ToViews(SkakelState state) =>
        [.. state.Clients.Select(c => new SkakelClientView(
            c.Id,
            c.Name,
            c.CreatedAt,
            _lastSeen.TryGetValue(c.Id, out var seen) ? seen : null,
            state.NextCertificate?.ReceivedBy.Contains(c.Id) == true,
            c.Secret is not null))];

    /// <summary>Tells the app's UI what changed, from the state as it is now, so a late event never shows an older list.</summary>
    private async Task RaiseViewsAsync()
    {
        var clients = Clients;
        var raisedClients = Interlocked.Exchange(ref _raisedClients, clients);
        if (raisedClients is null || !raisedClients.SequenceEqual(clients))
        {
            await ClientsChanged.RaiseAsync(clients, _logger);
        }

        var keys = KeysView;
        if (Interlocked.Exchange(ref _raisedKeys, keys) != keys)
        {
            await KeysChanged.RaiseAsync(keys, _logger);
        }
    }

    public void Dispose()
    {
        _prune.Dispose();
        _write.Dispose();
        lock (_applying)
        {
            _keysChanged.Dispose();
            _certificate?.Dispose();
            foreach (var certificate in _replaced)
            {
                certificate.Dispose();
            }

            foreach (var key in _rsaKeys.Values)
            {
                key.Rsa?.Dispose();
            }
        }
    }

    /// <summary>
    /// Loads what changed: the signing keys (and tells the token server and the validation), the
    /// certificate presented, and the next certificate's fingerprint. A replaced certificate is kept
    /// until the server is disposed, because a TLS handshake may still be using it.
    /// </summary>
    private void Apply(SkakelState state)
    {
        var now = _time.GetUtcNow();
        var retired = Unexpired(state.RetiredSigningKeys, now);
        var keysChanged = false;
        lock (_applying)
        {
            var source = string.Join('|', [state.SigningKey.KeyId, .. retired.Select(r => r.KeyId)]);
            if (source != _keysSource)
            {
                var signing = RsaKey(state.SigningKey);
                var validation = new List<SecurityKey> { signing };
                validation.AddRange(retired.Select(RsaKey));
                foreach (var stale in _rsaKeys.Keys.Except(validation.Select(k => k.KeyId)).ToList())
                {
                    // Not disposed: a token check that read the key a moment ago may still be using it.
                    _rsaKeys.Remove(stale);
                }

                Volatile.Write(ref _keys, new SigningKeys(signing, validation));
                _keysSource = source;
                keysChanged = true;
            }

            if (state.CertificatePfx != _certificatePfx)
            {
                var previous = _certificate;
                Volatile.Write(ref _certificate, ServerCertificate.Load(state.CertificatePfx));
                _certificatePfx = state.CertificatePfx;
                if (previous is not null)
                {
                    _replaced.Add(previous);
                }
            }

            var nextPfx = state.NextCertificate?.Pfx;
            if (nextPfx != _nextPfx)
            {
                Volatile.Write(ref _nextFingerprint, nextPfx is null ? null : FingerprintOf(nextPfx));
                _nextPfx = nextPfx;
            }
        }

        if (keysChanged)
        {
            try
            {
                // The token server and the validation build their options again, with these keys, before this returns.
                // Not disposed: a change token handed out a moment ago may still register on it.
                Interlocked.Exchange(ref _keysChanged, new CancellationTokenSource()).Cancel();
            }
            catch (AggregateException ex)
            {
                LogKeysNotApplied(ex);
            }
        }

        // Wake up when the first replaced key is due to go.
        _prune.Change(retired.Count > 0 ? Max(retired.Min(r => r.AcceptUntil!.Value) - now, TimeSpan.Zero) : Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
    }

    /// <summary>Drops the replaced keys whose tokens have all expired. A failure is logged and tried again in a minute.</summary>
    private async Task PruneRetiredKeysAsync()
    {
        try
        {
            var now = _time.GetUtcNow();
            await UpdateAsync(current => current.RetiredSigningKeys.Any(r => r.AcceptUntil <= now)
                ? current with { RetiredSigningKeys = Unexpired(current.RetiredSigningKeys, now) }
                : current, CancellationToken.None);
        }
        catch (Exception ex)
        {
            LogPruneFailed(ex);
            _prune.Change(TimeSpan.FromMinutes(1), Timeout.InfiniteTimeSpan);
        }
    }

    private RsaSecurityKey RsaKey(SkakelKeyRecord record)
    {
        if (!_rsaKeys.TryGetValue(record.KeyId, out var key))
        {
            var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(record.PrivateKey), out _);
            key = new RsaSecurityKey(rsa) { KeyId = record.KeyId };
            _rsaKeys[record.KeyId] = key;
        }

        return key;
    }

    private string NewCertificate(DateTimeOffset now) =>
        Convert.ToBase64String(ServerCertificate.CreatePfx(_options.CertificateHostName, _options.AppId, now));

    private static SkakelKeyRecord NewSigningKey(DateTimeOffset now)
    {
        using var rsa = RSA.Create(2048);
        return new SkakelKeyRecord(Secrets.NewId("skakel"), Convert.ToBase64String(rsa.ExportPkcs8PrivateKey()), now);
    }

    private static List<SkakelKeyRecord> Unexpired(IReadOnlyList<SkakelKeyRecord> retired, DateTimeOffset now) =>
        [.. retired.Where(r => r.AcceptUntil > now)];

    private static TimeSpan Max(TimeSpan a, TimeSpan b) => a > b ? a : b;

    private static string FingerprintOf(string pfx)
    {
        using var certificate = ServerCertificate.Load(pfx);
        return Fingerprints.Of(certificate);
    }

    private static InvalidOperationException NotLoaded() => new("The Skakel server has not started yet.");

    /// <summary>The key that signs, and every key a live token may carry, the signing key first.</summary>
    private sealed record SigningKeys(RsaSecurityKey Signing, IReadOnlyList<SecurityKey> Validation);

    [LoggerMessage(Level = LogLevel.Error, Message = "The token server did not take the new signing keys")]
    private partial void LogKeysNotApplied(Exception exception);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Could not drop the expired token signing keys; trying again in a minute")]
    private partial void LogPruneFailed(Exception exception);
}
