using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace Skakel.Client;

/// <summary>
/// Finds where a link's server went, as when it came back on another port after an upgrade, or its
/// machine got a new IP address. While the link cannot reach the saved address at all, and discovery
/// hears a server with the pinned certificate (or the next one) somewhere else, that is where it moved.
/// The fingerprint in a discovery answer is public, so anyone on the network can copy it: before the
/// move, the new address must prove it holds the certificate over a pinned handshake, so a copied answer
/// cannot draw the client away from its server. Every address heard with a trusted fingerprint is a
/// candidate, not only the one the browser lists first, so a copy cannot hide the real server either;
/// up to <see cref="MaxProofs"/> are tried per search, and one that failed its proof goes to the back
/// of the queue, so the next search gets to the others.
/// </summary>
internal sealed partial class ServerMoves(TimeProvider time, ILogger logger) : IDisposable
{
    /// <summary>How long an address the link moved to is not moved to again, so two addresses that both fail cannot take turns.</summary>
    internal static readonly TimeSpan HoldOff = TimeSpan.FromMinutes(5);

    /// <summary>How long an address has to prove it holds the pinned certificate.</summary>
    internal static readonly TimeSpan ProofTimeout = TimeSpan.FromSeconds(5);

    /// <summary>The most addresses one search tries to prove.</summary>
    internal const int MaxProofs = 8;

    /// <summary>How long the saved host name may take to resolve, when working out whether a server is on the same host.</summary>
    private static readonly TimeSpan ResolveTimeout = TimeSpan.FromSeconds(5);

    private readonly SemaphoreSlim _moving = new(1, 1);
    private readonly Dictionary<string, DateTimeOffset> _movedTo = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTimeOffset> _failed = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The address to move to, or null. One search at a time. Each candidate, best first and at most
    /// <see cref="MaxProofs"/>, gets one proof (<paramref name="proves"/>); the first that passes is the
    /// answer, and is held off from now. <paramref name="servers"/> is every address discovery heard, not
    /// one per fingerprint.
    /// </summary>
    public async Task<Uri?> FindAsync(Uri saved, SkakelPins pins, IReadOnlyList<SkakelDiscoveredServer> servers, Func<Uri, Task<bool>> proves, CancellationToken cancellationToken)
    {
        if (!servers.Any(s => pins.Trusts(s.Fingerprint)))
        {
            return null;
        }

        await _moving.WaitAsync(cancellationToken);
        try
        {
            var now = time.GetUtcNow();
            Forget(_movedTo, now);
            Forget(_failed, now);
            foreach (var url in Candidates(saved, pins, servers, await AddressesOfAsync(saved), _movedTo.ContainsKey, a => _failed.TryGetValue(a, out var at) ? at : null))
            {
                if (await proves(url))
                {
                    _movedTo[url.Authority] = now;
                    _failed.Remove(url.Authority);
                    return url;
                }

                _failed[url.Authority] = time.GetUtcNow();
            }

            return null;
        }
        finally
        {
            _moving.Release();
        }
    }

    public void Dispose() => _moving.Dispose();

    /// <summary>
    /// The addresses a link at <paramref name="saved"/> could move to, best first and at most
    /// <see cref="MaxProofs"/>: where discovery hears a server with a certificate it trusts, other than
    /// the saved address. One on the saved host (<paramref name="savedHost"/>) on another port comes
    /// first, and keeps the saved host name; then any other, in the order discovery has them. One that
    /// failed a proof (<paramref name="failedAt"/>) comes after those that did not, the longest ago first.
    /// An address moved to a little while ago is <paramref name="heldOff"/>.
    /// </summary>
    internal static IReadOnlyList<Uri> Candidates(Uri saved, SkakelPins pins, IEnumerable<SkakelDiscoveredServer> servers, IReadOnlyCollection<IPAddress> savedHost, Func<string, bool>? heldOff = null, Func<string, DateTimeOffset?>? failedAt = null) =>
        [.. servers
            .Where(s => pins.Trusts(s.Fingerprint))
            .Select(s =>
            {
                var sameHost = savedHost.Contains(Plain(s.Address));
                var url = sameHost ? new UriBuilder(saved) { Port = s.Port }.Uri : s.Url;
                return (SameHost: sameHost, Url: new Uri(url.GetLeftPart(UriPartial.Authority) + "/"));
            })
            .Where(c => !string.Equals(c.Url.Authority, saved.Authority, StringComparison.OrdinalIgnoreCase) && heldOff?.Invoke(c.Url.Authority) != true)
            .DistinctBy(c => c.Url.Authority, StringComparer.OrdinalIgnoreCase)
            .Select(c => (c.SameHost, c.Url, Failed: failedAt?.Invoke(c.Url.Authority)))
            .OrderBy(c => c.Failed is not null)
            .ThenByDescending(c => c.SameHost)
            .ThenBy(c => c.Failed)
            .Take(MaxProofs)
            .Select(c => c.Url)];

    /// <summary>Drops what is older than <see cref="HoldOff"/>.</summary>
    private static void Forget(Dictionary<string, DateTimeOffset> times, DateTimeOffset now)
    {
        foreach (var (authority, at) in times.ToList())
        {
            if (now - at >= HoldOff)
            {
                times.Remove(authority);
            }
        }
    }

    /// <summary>The addresses the saved host stands for: itself when it is one, otherwise what its name resolves to now, or none.</summary>
    private async Task<IReadOnlyCollection<IPAddress>> AddressesOfAsync(Uri saved)
    {
        if (IPAddress.TryParse(saved.IdnHost, out var literal))
        {
            return [Plain(literal)];
        }

        using var timeout = new CancellationTokenSource(ResolveTimeout);
        try
        {
            return [.. (await Dns.GetHostAddressesAsync(saved.IdnHost, timeout.Token)).Select(Plain)];
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            LogNotResolved(saved.IdnHost, ex.Message);
            return [];
        }
    }

    private static IPAddress Plain(IPAddress address) => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    [LoggerMessage(Level = LogLevel.Information, Message = "Could not resolve {Host} to compare it with the servers on the network: {Reason}")]
    private partial void LogNotResolved(string host, string reason);
}
