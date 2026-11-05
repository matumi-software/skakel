using System.Net.Http.Json;
using Microsoft.Extensions.Logging;
using Skakel.Protocol;

namespace Skakel.Client;

/// <summary>
/// Reads a server's <c>GET /skakel/info</c>: its name, its app and the protocol versions it speaks. Over
/// a connection pinned to the server's fingerprints, so any answer also proves the server holds one of
/// those certificates. The answer is held to the limits discovery applies: the name and app version
/// cleaned and cut as <see cref="SkakelDiscovery.Clean"/> does, the app id a real one, and at most
/// 64 KB read.
/// </summary>
public static partial class SkakelInfoClient
{
    /// <summary>
    /// The server's info. Pick the version to speak with <see cref="SkakelVersions.Require"/>; this does
    /// not check it, so an app can still show the server's name when there is none.
    /// </summary>
    /// <param name="address">The server's HTTPS address, such as <c>https://pi-lab:5240</c>.</param>
    /// <param name="pins">The certificates to trust.</param>
    /// <param name="options">Logging, time and the request timeout.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <exception cref="SkakelException">The server could not be reached, presented another certificate, or did not answer like a Skakel server.</exception>
    public static async Task<SkakelInfo> ReadAsync(Uri address, SkakelPins pins, SkakelClientOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pins);
        var server = Pinning.BaseAddress(address, nameof(address));
        options ??= new SkakelClientOptions();
        using var handler = Pinning.CreateHandler(() => pins);
        using var http = Pinning.CreateClient(handler, options.RequestTimeout, disposeHandler: false);
        return await ReadAsync(http, server, options.Loggers.CreateLogger(typeof(SkakelInfoClient)), cancellationToken);
    }

    /// <summary>The same over a client the caller made, pinned and with its timeout.</summary>
    internal static async Task<SkakelInfo> ReadAsync(HttpClient http, Uri server, ILogger logger, CancellationToken cancellationToken)
    {
        try
        {
            using var response = await http.GetAsync(new Uri(server, SkakelProtocol.InfoPath), cancellationToken);
            response.EnsureSuccessStatusCode();
            var info = await response.Content.ReadFromJsonAsync<SkakelInfo>(SkakelJson.Options, cancellationToken);
            if (info is not { Name: { } name, App: { Id: var id, Version: { Length: <= SkakelDiscovery.MaxAppVersionLength } version }, Versions: { Count: > 0 } versions }
                || !SkakelProtocol.IsAppId(id)
                || versions.Any(v => v < 1))
            {
                throw new InvalidDataException("The info answer is missing the name, the app or the versions, or breaks their limits.");
            }

            // The same limits as discovery: a name a person can be shown, the address when that leaves nothing.
            var shown = SkakelDiscovery.Clean(name, SkakelDiscovery.MaxNameLength);
            return info with
            {
                Name = shown.Length > 0 ? shown : server.Host,
                App = new SkakelApp(id, SkakelDiscovery.Clean(version, SkakelDiscovery.MaxAppVersionLength)),
            };
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            LogFailed(logger, server.Authority, ex);
            throw Failures.Exception(ex);
        }
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Could not read the info of {Server}")]
    private static partial void LogFailed(ILogger logger, string server, Exception exception);
}
