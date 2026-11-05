namespace Skakel.Server;

/// <summary>What an app's UI shows about a registered client.</summary>
/// <param name="Id">The client ID.</param>
/// <param name="Name">What people call it.</param>
/// <param name="CreatedAt">When it was registered.</param>
/// <param name="LastSeen">When it last got a token, since this server started.</param>
/// <param name="HasNextCertificate">It stored the fingerprint of the prepared next certificate.</param>
/// <param name="HasSecret">Its secret is kept, so <see cref="SkakelClients.SecretOf"/> can show it again.</param>
public sealed record SkakelClientView(string Id, string Name, DateTimeOffset CreatedAt, DateTimeOffset? LastSeen, bool HasNextCertificate, bool HasSecret);

/// <summary>A client just registered, with the secret it signs in with.</summary>
/// <param name="ClientId">The client ID.</param>
/// <param name="Name">What people call it.</param>
/// <param name="ClientSecret">The secret.</param>
public sealed record SkakelNewClient(string ClientId, string Name, string ClientSecret);

/// <summary>
/// The clients registered with this server. Registering is also what an approved pairing does.
/// Revoking a client or rotating its secret ends its hub connections and streams at once, after
/// telling its hub connections why.
/// </summary>
public sealed class SkakelClients
{
    private readonly ServerState _state;

    internal SkakelClients(ServerState state) => _state = state;

    /// <summary>Raised after the clients changed: one was added, revoked or rotated, or stored the next certificate.</summary>
    public event Func<IReadOnlyList<SkakelClientView>, Task>? Changed
    {
        add => _state.ClientsChanged += value;
        remove => _state.ClientsChanged -= value;
    }

    /// <summary>Every registered client.</summary>
    public IReadOnlyList<SkakelClientView> All => _state.Clients;

    /// <summary>Registers a client. The secret is in the result, and is kept only with <see cref="SkakelServerOptions.KeepClientSecrets"/>.</summary>
    /// <param name="name">What people call it, such as the machine it runs on. Control and format characters are taken out and the rest trimmed, as for a name that comes in by pairing.</param>
    /// <exception cref="ArgumentException">Nothing is left of the name.</exception>
    /// <param name="cancellationToken">Cancels the save.</param>
    public Task<SkakelNewClient> RegisterAsync(string name, CancellationToken cancellationToken = default) => _state.RegisterClientAsync(name, cancellationToken);

    /// <summary>
    /// Gives the client a new secret. The old one stops working at once, and so does every token issued
    /// before, because the client's generation goes up. The new secret, or null when there is no such client.
    /// </summary>
    /// <param name="clientId">The client.</param>
    /// <param name="cancellationToken">Cancels the save.</param>
    public Task<string?> RotateSecretAsync(string clientId, CancellationToken cancellationToken = default) => _state.RotateSecretAsync(clientId, cancellationToken);

    /// <summary>Removes the client. Its tokens stop working at once. False when there is no such client.</summary>
    /// <param name="clientId">The client.</param>
    /// <param name="cancellationToken">Cancels the save.</param>
    public Task<bool> RevokeAsync(string clientId, CancellationToken cancellationToken = default) => _state.RevokeClientAsync(clientId, cancellationToken);

    /// <summary>The client's name, or null when there is no such client.</summary>
    /// <param name="clientId">The client.</param>
    public string? NameOf(string? clientId) => _state.Find(clientId)?.Name;

    /// <summary>The client's secret when it is kept; null when it is not, or there is no such client.</summary>
    /// <param name="clientId">The client.</param>
    public string? SecretOf(string clientId) => _state.Find(clientId)?.Secret;
}
