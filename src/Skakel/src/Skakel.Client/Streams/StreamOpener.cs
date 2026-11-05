using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http.Headers;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Skakel.Protocol;

namespace Skakel.Client;

/// <summary>
/// Opens a stream with the WebSocket upgrade written out by hand, over the link's pinned handler, as the
/// runtime's own <see cref="ClientWebSocket"/> does inside. Done here so a refusal keeps its body: the
/// server checks everything before the upgrade, and its problem <c>detail</c> is what a person reads.
/// </summary>
internal static class StreamOpener
{
    /// <summary>The most of a refusal's body that is read.</summary>
    private const int MaxProblemBytes = 16 * 1024;

    /// <summary>RFC 6455's GUID for the accept key.</summary>
    private const string AcceptGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    public static Uri Path(Uri server, string type, IEnumerable<KeyValuePair<string, string>>? query)
    {
        var builder = new UriBuilder(new Uri(server, $"{SkakelProtocol.StreamsPath}/{type}"));
        if (query is not null)
        {
            builder.Query = string.Join('&', query.Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value ?? "")}"));
        }

        return builder.Uri;
    }

    /// <summary>
    /// Asks for the upgrade. The stream, or the refusal with its status and detail. The upgrade and the
    /// reading of a refusal together take at most <paramref name="timeout"/>; an open stream has no
    /// time limit of its own.
    /// </summary>
    /// <exception cref="TimeoutException">The server did not answer within <paramref name="timeout"/>, inside a <see cref="TaskCanceledException"/> as <see cref="HttpClient"/> reports it.</exception>
    public static async Task<SkakelOpenResult<SkakelStreamConnection>> OpenAsync(HttpMessageInvoker invoker, Uri uri, string type, string token, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        using var request = new HttpRequestMessage(HttpMethod.Get, uri)
        {
            Version = HttpVersion.Version11,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };
        request.Headers.TryAddWithoutValidation("Connection", "Upgrade");
        request.Headers.TryAddWithoutValidation("Upgrade", "websocket");
        request.Headers.TryAddWithoutValidation("Sec-WebSocket-Version", "13");
        request.Headers.TryAddWithoutValidation("Sec-WebSocket-Key", key);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        limit.CancelAfter(timeout);
        HttpResponseMessage response;
        try
        {
            response = await invoker.SendAsync(request, limit.Token);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw TimedOut(timeout, ex);
        }

        try
        {
            if (response.StatusCode != HttpStatusCode.SwitchingProtocols)
            {
                var refusal = SkakelStreamRefusal.From((int)response.StatusCode, await ReadDetailAsync(response, limit.Token));
                cancellationToken.ThrowIfCancellationRequested();
                response.Dispose();
                return SkakelOpenResult<SkakelStreamConnection>.Refused(refusal);
            }

            if (!response.Headers.TryGetValues("Sec-WebSocket-Accept", out var accepts) || accepts.ToList() is not [var accept] || accept != Accept(key))
            {
                throw new InvalidDataException("The server switched protocols without a single WebSocket accept for this key.");
            }

            var connection = await response.Content.ReadAsStreamAsync(cancellationToken);
            var socket = WebSocket.CreateFromStream(connection, new WebSocketCreationOptions
            {
                IsServer = false,
                KeepAliveInterval = SkakelProtocol.StreamKeepAliveInterval,
                KeepAliveTimeout = SkakelProtocol.StreamKeepAliveTimeout,
            });
            return SkakelOpenResult<SkakelStreamConnection>.Opened(new SkakelStreamConnection(type, socket, response));
        }
        catch
        {
            response.Dispose();
            throw;
        }
    }

    private static TaskCanceledException TimedOut(TimeSpan timeout, Exception cause) =>
        new($"The stream did not open within {timeout.TotalSeconds:0.#} seconds.", new TimeoutException("The request timed out.", cause));

    [SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "RFC 6455 defines the accept key with SHA-1. It shows the server understood the upgrade; it protects nothing.")]
    private static string Accept(string key) => Convert.ToBase64String(SHA1.HashData(Encoding.ASCII.GetBytes(key + AcceptGuid)));

    /// <summary>The problem's <c>detail</c>, or null when the body is not a problem.</summary>
    private static async Task<string?> ReadDetailAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        try
        {
            await using var body = await response.Content.ReadAsStreamAsync(cancellationToken);
            var buffer = new byte[MaxProblemBytes];
            var length = 0;
            int read;
            while (length < buffer.Length && (read = await body.ReadAsync(buffer.AsMemory(length), cancellationToken)) > 0)
            {
                length += read;
            }

            return JsonSerializer.Deserialize<SkakelProblem>(buffer.AsSpan(0, length), SkakelJson.Options)?.Detail;
        }
        catch (Exception ex) when (ex is JsonException or IOException or HttpRequestException or OperationCanceledException)
        {
            // A body that is not a problem, or that took too long: the status alone still says why.
            return null;
        }
    }
}
