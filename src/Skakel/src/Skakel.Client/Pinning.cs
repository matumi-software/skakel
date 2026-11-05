using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Skakel.Protocol;

namespace Skakel.Client;

/// <summary>
/// HTTP handlers that trust exactly the certificates a server is pinned to and nothing else.
/// Self-signed is fine; that is the point of pinning. The pins are read at each handshake, so a
/// handler made before a handover trusts the new certificate once the link learned it.
/// </summary>
/// <remarks>
/// A Skakel server is on the local network, so the handlers never go through a proxy: a system proxy
/// would see every request's address, and could not reach most LAN addresses anyway. A pooled
/// connection lives at most <see cref="ConnectionLifetime"/>, so one made under a pin the link has
/// since dropped does not stay in use.
/// </remarks>
internal static class Pinning
{
    /// <summary>How long opening a TCP connection may take.</summary>
    public static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(10);

    /// <summary>How long a pooled connection is reused before a new one, with a new handshake, takes its place.</summary>
    public static readonly TimeSpan ConnectionLifetime = TimeSpan.FromMinutes(1);

    /// <summary>The most of any answer the library reads: info, pairing, tokens, hello and the hub's negotiation are all far smaller.</summary>
    public const int MaxResponseBytes = 64 * 1024;

    /// <param name="pins">The certificates to trust, read at each handshake.</param>
    /// <param name="presented">Told the fingerprint of each certificate a handshake trusted, when given.</param>
    public static SocketsHttpHandler CreateHandler(Func<SkakelPins> pins, Action<string>? presented = null)
    {
        ArgumentNullException.ThrowIfNull(pins);
        return new SocketsHttpHandler
        {
            // A pinned server never sends a client elsewhere; a redirect is not followed.
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false,
            ConnectTimeout = ConnectTimeout,
            PooledConnectionLifetime = ConnectionLifetime,
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, certificate, _, _) => Trusts(pins(), certificate as X509Certificate2, presented),
            },
        };
    }

    /// <summary>
    /// For the SignalR client: the pinned handler, kept to the server's own address over HTTPS, so a
    /// negotiation that points elsewhere is not followed, and with the negotiation's answer bounded.
    /// SignalR disposes it with the connection.
    /// </summary>
    /// <param name="server">The server's base address.</param>
    /// <param name="pins">The certificates to trust.</param>
    /// <param name="presented">Told the fingerprint of each certificate a handshake trusted.</param>
    public static HttpMessageHandler CreateHubHandler(Uri server, Func<SkakelPins> pins, Action<string>? presented = null) =>
        new HubGuard(server, CreateHandler(pins, presented));

    /// <summary>An HTTP client over a pinned handler, with the request timeout and the bound on what it reads.</summary>
    public static HttpClient CreateClient(HttpMessageHandler handler, TimeSpan timeout, bool disposeHandler = true) =>
        new(handler, disposeHandler) { Timeout = timeout, MaxResponseContentBufferSize = MaxResponseBytes };

    /// <summary>True for an absolute HTTPS address at <paramref name="server"/>'s host and port.</summary>
    public static bool IsAt(Uri? address, Uri server) =>
        address is { IsAbsoluteUri: true }
        && address.Scheme == Uri.UriSchemeHttps
        && Uri.Compare(address, server, UriComponents.SchemeAndServer, UriFormat.SafeUnescaped, StringComparison.OrdinalIgnoreCase) == 0;

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

    /// <summary>Whether the pins trust the certificate, telling <paramref name="presented"/> when they do.</summary>
    public static bool Trusts(SkakelPins pins, X509Certificate2? certificate, Action<string>? presented)
    {
        if (!pins.Trusts(certificate))
        {
            return false;
        }

        presented?.Invoke(Fingerprints.Of(certificate!));
        return true;
    }

    /// <summary>
    /// Sends the hub's requests only to the server's own address, over HTTPS, and reads the
    /// negotiation's answer within <see cref="MaxResponseBytes"/>. Long polling and server-sent events
    /// stream their answers and are left as they are.
    /// </summary>
    private sealed class HubGuard(Uri server, HttpMessageHandler inner) : DelegatingHandler(inner)
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (!IsAt(request.RequestUri, server))
            {
                throw new InvalidDataException("The hub's negotiation pointed away from the server's own address.");
            }

            var response = await base.SendAsync(request, cancellationToken);
            if (request.RequestUri!.AbsolutePath.EndsWith("/negotiate", StringComparison.Ordinal))
            {
                try
                {
                    await response.Content.LoadIntoBufferAsync(MaxResponseBytes, cancellationToken);
                }
                catch
                {
                    response.Dispose();
                    throw;
                }
            }

            return response;
        }
    }
}
