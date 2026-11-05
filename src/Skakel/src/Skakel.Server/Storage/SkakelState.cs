namespace Skakel.Server;

/// <summary>
/// Everything a Skakel server must keep across restarts: its clients, its token signing keys and its
/// certificates. It holds private keys and, with <see cref="SkakelServerOptions.KeepClientSecrets"/>,
/// client secrets, so the app keeps it where only the server can read it.
/// </summary>
public sealed record SkakelState
{
    /// <summary>The registered clients.</summary>
    public required IReadOnlyList<SkakelClientRecord> Clients { get; init; }

    /// <summary>The key new access tokens are signed with.</summary>
    public required SkakelKeyRecord SigningKey { get; init; }

    /// <summary>Keys that no longer sign, kept until every token they signed has expired.</summary>
    public IReadOnlyList<SkakelKeyRecord> RetiredSigningKeys { get; init; } = [];

    /// <summary>The certificate the server presents, as base64 PKCS#12 with its private key and no password.</summary>
    public required string CertificatePfx { get; init; }

    /// <summary>The certificate prepared for a handover, or null when none is.</summary>
    public SkakelNextCertificateRecord? NextCertificate { get; init; }
}

/// <summary>A registered client.</summary>
/// <param name="Id">The client ID, such as <c>client-3f9a1c2b7d</c>.</param>
/// <param name="Name">What people call it.</param>
/// <param name="SecretHash">The hash its secret is checked against.</param>
/// <param name="CreatedAt">When it was registered.</param>
/// <param name="Generation">Raised by each rotation of the secret. Tokens carry it, and only the current one is accepted.</param>
/// <param name="Secret">The secret itself, kept only with <see cref="SkakelServerOptions.KeepClientSecrets"/>.</param>
public sealed record SkakelClientRecord(string Id, string Name, string SecretHash, DateTimeOffset CreatedAt, int Generation = 1, string? Secret = null);

/// <summary>A token signing key.</summary>
/// <param name="KeyId">The key id, which goes in each token's header.</param>
/// <param name="PrivateKey">The RSA private key as base64 PKCS#8.</param>
/// <param name="CreatedAt">When it was made.</param>
/// <param name="AcceptUntil">For a retired key: when the last token it signed has expired. Null for the signing key.</param>
public sealed record SkakelKeyRecord(string KeyId, string PrivateKey, DateTimeOffset CreatedAt, DateTimeOffset? AcceptUntil = null);

/// <summary>The certificate the server presents after the switch, kept beside the current one while clients learn its fingerprint.</summary>
/// <param name="Pfx">Base64 PKCS#12 with its private key and no password.</param>
/// <param name="PreparedAt">When it was made.</param>
/// <param name="ReceivedBy">The IDs of the clients that said they stored its fingerprint.</param>
public sealed record SkakelNextCertificateRecord(string Pfx, DateTimeOffset PreparedAt, IReadOnlyList<string> ReceivedBy);
