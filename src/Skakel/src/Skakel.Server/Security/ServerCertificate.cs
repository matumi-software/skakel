using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Skakel.Server.Security;

/// <summary>
/// The self-signed certificate a Skakel server presents. Clients trust it by its SHA-256 fingerprint,
/// which the app shows people.
/// </summary>
internal static class ServerCertificate
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromDays(3650);

    /// <summary>A new self-signed ECDSA P-256 certificate, valid for ten years, exported as PKCS#12.</summary>
    public static byte[] CreatePfx(string hostName, string organization, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hostName);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var subject = new X500DistinguishedNameBuilder();
        subject.AddCommonName(hostName);
        subject.AddOrganizationName(organization);
        var request = new CertificateRequest(subject.Build(), key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], critical: false));
        var names = new SubjectAlternativeNameBuilder();
        try
        {
            names.AddDnsName(hostName);
        }
        catch (ArgumentException)
        {
            // A name that is not a DNS name; clients pin the fingerprint, not the name.
        }

        names.AddDnsName("localhost");
        request.CertificateExtensions.Add(names.Build());

        using var certificate = request.CreateSelfSigned(now.AddDays(-1), now + Lifetime);
        return certificate.Export(X509ContentType.Pfx);
    }

    /// <remarks>
    /// Windows' TLS stack cannot use an ephemeral private key for a server, so there the key goes into a
    /// temporary key container that is removed when the certificate is disposed.
    /// </remarks>
    public static X509Certificate2 Load(string pfx) =>
        X509CertificateLoader.LoadPkcs12(Convert.FromBase64String(pfx), password: null, OperatingSystem.IsWindows() ? X509KeyStorageFlags.DefaultKeySet : X509KeyStorageFlags.EphemeralKeySet);
}
