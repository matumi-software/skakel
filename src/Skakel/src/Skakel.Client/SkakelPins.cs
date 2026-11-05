using System.Security.Cryptography.X509Certificates;
using Skakel.Protocol;

namespace Skakel.Client;

/// <summary>
/// The certificates a client trusts for one server: the pinned one and, while the server hands over to
/// a new certificate, the next one. The app keeps them beside the server's address and credentials, and
/// saves them again when a link says they changed.
/// </summary>
public sealed record SkakelPins
{
    /// <summary>Pins a server's certificate.</summary>
    /// <param name="fingerprint">The pinned fingerprint: 64 hex digits, with or without colons.</param>
    /// <param name="nextFingerprint">The certificate the server said it will switch to, or null.</param>
    /// <exception cref="ArgumentException">A fingerprint is not 64 hex digits.</exception>
    public SkakelPins(string fingerprint, string? nextFingerprint = null)
    {
        Fingerprint = Fingerprints.Normalize(fingerprint) ?? throw new ArgumentException("A fingerprint is 64 hex digits.", nameof(fingerprint));
        NextFingerprint = nextFingerprint is null ? null
            : Fingerprints.Normalize(nextFingerprint) ?? throw new ArgumentException("A fingerprint is 64 hex digits.", nameof(nextFingerprint));
        if (Fingerprints.AreEqual(Fingerprint, NextFingerprint))
        {
            NextFingerprint = null;
        }
    }

    /// <summary>The pinned fingerprint, in colon form.</summary>
    public string Fingerprint { get; }

    /// <summary>The certificate the server will switch to, trusted as well until then, or null.</summary>
    public string? NextFingerprint { get; }

    /// <summary>True when <paramref name="certificate"/> is the pinned certificate or the next one.</summary>
    /// <param name="certificate">What the server presented.</param>
    public bool Trusts(X509Certificate2? certificate) => Fingerprints.MatchesAny(certificate, Fingerprint, NextFingerprint);

    /// <summary>True when <paramref name="fingerprint"/> is the pinned fingerprint or the next one.</summary>
    /// <param name="fingerprint">A fingerprint, in any form.</param>
    public bool Trusts(string? fingerprint) => Fingerprints.AreEqual(fingerprint, Fingerprint) || Fingerprints.AreEqual(fingerprint, NextFingerprint);

    /// <summary>
    /// What the server said about its certificates, over a connection pinned to one of these. When it now
    /// presents the next one, that becomes the pinned one; either way the next one is what it says, or
    /// none. A statement about a certificate these pins do not know changes nothing.
    /// </summary>
    internal SkakelPins WithServerCertificates(string fingerprint, string? next)
    {
        var current = Fingerprints.AreEqual(fingerprint, Fingerprint) ? Fingerprint
            : Fingerprints.AreEqual(fingerprint, NextFingerprint) ? NextFingerprint
            : null;
        return current is null ? this : new SkakelPins(current, next);
    }
}

/// <summary>What a client signs in to one server with. Pairing hands them over; the app keeps them, and the secret only where it keeps secrets.</summary>
/// <param name="ClientId">The client's ID on that server.</param>
/// <param name="ClientSecret">The client's secret on that server.</param>
public sealed record SkakelCredentials(string ClientId, string ClientSecret)
{
    /// <summary>The client ID, never the secret, so a log line cannot leak it.</summary>
    public override string ToString() => $"{nameof(SkakelCredentials)} {{ {nameof(ClientId)} = {ClientId} }}";
}
