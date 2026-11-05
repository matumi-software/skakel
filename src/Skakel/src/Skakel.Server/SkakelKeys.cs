using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;

namespace Skakel.Server;

/// <summary>What an app's UI shows about the server's certificate and its token signing key.</summary>
/// <param name="Fingerprint">The certificate the server presents.</param>
/// <param name="NextFingerprint">The prepared next certificate, or null when none is prepared.</param>
/// <param name="NextPreparedAt">When the next certificate was prepared.</param>
/// <param name="SigningKeyId">The key id of the key that signs new tokens.</param>
/// <param name="SigningKeySince">When that key was made.</param>
/// <param name="RetiredKeysUntil">While keys it replaced are still accepted, when the last of them is dropped.</param>
public sealed record SkakelKeysView(string Fingerprint, string? NextFingerprint, DateTimeOffset? NextPreparedAt, string SigningKeyId, DateTimeOffset SigningKeySince, DateTimeOffset? RetiredKeysUntil);

/// <summary>What a switch to the next certificate did.</summary>
/// <param name="From">The fingerprint presented before.</param>
/// <param name="To">The fingerprint presented now.</param>
/// <param name="NotReceived">The names of the clients that had not stored the new fingerprint, and will have to pair again.</param>
public sealed record SkakelCertificateSwitch(string From, string To, IReadOnlyList<string> NotReceived);

/// <summary>
/// The server's certificate and its token signing key, and replacing them.
/// </summary>
/// <remarks>
/// The certificate is replaced in a handover, so pinned clients are not cut off: prepare the next one,
/// let the clients learn its fingerprint over the hub (<see cref="SkakelClientView.HasNextCertificate"/>
/// says who has), then switch. A new signing key signs at once, and the one it replaced is still
/// accepted until every token it signed has expired.
/// </remarks>
public sealed class SkakelKeys
{
    private readonly ServerState _state;

    internal SkakelKeys(ServerState state) => _state = state;

    /// <summary>Raised after the certificates or the signing key changed.</summary>
    public event Func<SkakelKeysView, Task>? Changed
    {
        add => _state.KeysChanged += value;
        remove => _state.KeysChanged -= value;
    }

    /// <summary>The certificate the server presents. After a switch it is the new one, at once, for every new connection.</summary>
    public X509Certificate2 Certificate => _state.Certificate;

    /// <summary>The fingerprint of <see cref="Certificate"/>.</summary>
    public string Fingerprint => _state.Fingerprint;

    /// <summary>The prepared next certificate's fingerprint, or null when none is prepared.</summary>
    public string? NextFingerprint => _state.NextFingerprint;

    /// <summary>What the UI shows.</summary>
    public SkakelKeysView View => _state.KeysView;

    /// <summary>
    /// Makes the next certificate and keeps it beside the current one, which the server goes on
    /// presenting. Connected clients are told its fingerprint. Returns it, or null when one is already prepared.
    /// </summary>
    /// <param name="cancellationToken">Cancels the save.</param>
    public Task<string?> PrepareNextCertificateAsync(CancellationToken cancellationToken = default) => _state.PrepareCertificateAsync(cancellationToken);

    /// <summary>Drops the prepared certificate; clients are told to forget it. False when none was prepared.</summary>
    /// <param name="cancellationToken">Cancels the save.</param>
    public Task<bool> CancelNextCertificateAsync(CancellationToken cancellationToken = default) => _state.CancelCertificateAsync(cancellationToken);

    /// <summary>
    /// Presents the prepared certificate from now on; the old one is gone. Connections already open carry
    /// on over the old one, and are told. Returns what changed, or null when none was prepared.
    /// </summary>
    /// <param name="cancellationToken">Cancels the save.</param>
    public Task<SkakelCertificateSwitch?> SwitchCertificateAsync(CancellationToken cancellationToken = default) => _state.SwitchCertificateAsync(cancellationToken);

    /// <summary>Makes a new token signing key and signs with it from now on. Returns its key id.</summary>
    /// <param name="cancellationToken">Cancels the save.</param>
    public Task<string> RotateSigningKeyAsync(CancellationToken cancellationToken = default) => _state.RotateSigningKeyAsync(cancellationToken);
}

/// <summary>Plugs the Skakel certificate into Kestrel.</summary>
public static class SkakelHttpsExtensions
{
    /// <summary>
    /// Presents the server's Skakel certificate on this HTTPS endpoint, the current one at each
    /// handshake, so a switch takes effect at once. Pass Kestrel's <c>ApplicationServices</c>.
    /// </summary>
    /// <example><code>
    /// builder.WebHost.ConfigureKestrel(kestrel => kestrel.ListenAnyIP(5240, listen =>
    ///     listen.UseHttps(https => https.UseSkakelCertificate(kestrel.ApplicationServices))));
    /// </code></example>
    /// <param name="https">The endpoint's HTTPS options.</param>
    /// <param name="services">The app's services.</param>
    public static HttpsConnectionAdapterOptions UseSkakelCertificate(this HttpsConnectionAdapterOptions https, IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(https);
        ArgumentNullException.ThrowIfNull(services);
        https.ServerCertificateSelector = (_, _) => services.GetRequiredService<SkakelKeys>().Certificate;
        return https;
    }
}
