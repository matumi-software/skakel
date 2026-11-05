using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Skakel.Client;

/// <summary>
/// HTTP handlers that trust exactly the certificates a server is pinned to and nothing else.
/// Self-signed is fine; that is the point of pinning. The pins are read at each handshake, so a
/// handler made before a handover trusts the new certificate once the link learned it.
/// </summary>
internal static class Pinning
{
    /// <summary>How long opening a TCP connection may take.</summary>
    public static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(10);

    public static SocketsHttpHandler CreateHandler(Func<SkakelPins> pins)
    {
        ArgumentNullException.ThrowIfNull(pins);
        return new SocketsHttpHandler
        {
            // A pinned server never sends a client elsewhere; a redirect is not followed.
            AllowAutoRedirect = false,
            UseCookies = false,
            ConnectTimeout = ConnectTimeout,
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, certificate, _, _) => pins().Trusts(certificate as X509Certificate2),
            },
        };
    }

    /// <summary>For the SignalR client, which takes an <see cref="HttpClientHandler"/> and disposes it with the connection.</summary>
    public static HttpClientHandler CreateHubHandler(Func<SkakelPins> pins)
    {
        ArgumentNullException.ThrowIfNull(pins);
        return new HttpClientHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            ServerCertificateCustomValidationCallback = (_, certificate, _, _) => pins().Trusts(certificate),
        };
    }

    /// <summary>The server's base address: HTTPS, scheme, host and port only.</summary>
    /// <exception cref="ArgumentException">Not an absolute HTTPS address.</exception>
    public static Uri BaseAddress(Uri address, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(address, parameterName);
        if (!address.IsAbsoluteUri || address.Scheme != Uri.UriSchemeHttps)
        {
            throw new ArgumentException("A Skakel server's address is an absolute https:// address.", parameterName);
        }

        return new Uri(address.GetLeftPart(UriPartial.Authority) + "/");
    }
}
