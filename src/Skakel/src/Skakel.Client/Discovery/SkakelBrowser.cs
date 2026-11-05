using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Skakel.Protocol;

namespace Skakel.Client;

/// <summary>
/// Finds an app's servers on the local network: broadcasts a probe every ten seconds to the app's port
/// on every IPv4 network this machine is on, and lists the servers that answer. Anyone on the network
/// can answer anything, so what it keeps is bounded by the limits in the protocol: answers only shortly
/// after a probe, at most 64 entries and 8 from one address, fingerprints that are really fingerprints,
/// short names, and entries that go when they stop answering.
/// </summary>
/// <remarks>
/// <para>
/// Entries are told apart by fingerprint, address and port, so an answer that copies another server's
/// name or fingerprint sits beside the real one instead of replacing it. The list shows one entry per
/// fingerprint: the address that answered first, on the best network. Every other address that answered
/// with the same fingerprint is in <see cref="SkakelDiscoveredServer.OtherEndpoints"/>, so an app can
/// warn that several addresses claim one certificate; only a pinned connection tells which holds it.
/// </para>
/// <para>One browser serves every link of an app; pass it to each in <see cref="SkakelClientOptions.Browser"/>.</para>
/// </remarks>
public sealed partial class SkakelBrowser : IDisposable
{
    /// <summary>How long after a probe its answers are taken. Later ones are dropped.</summary>
    internal static readonly TimeSpan AnswerWindow = TimeSpan.FromSeconds(3);

    private readonly IBrowseControl _control;
    private readonly TimeSpan _probeEvery;
    private readonly HashSet<string>? _appIds;
    private readonly Dictionary<EntryKey, Seen> _seen = [];
    // What running links have pinned. Their entries are never pushed out to make room.
    private readonly List<Func<SkakelPins>> _protected = [];
    private readonly Lock _gate = new();
    // Held around every start, stop and probe. The control's own threads take _gate, never this, so a stop can wait for them.
    private readonly Lock _browseLock = new();
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    // Only the latest list matters to anyone listening, so a slow listener skips the ones in between.
    private readonly Channel<IReadOnlyList<SkakelDiscoveredServer>> _changes = Channel.CreateBounded<IReadOnlyList<SkakelDiscoveredServer>>(
        new BoundedChannelOptions(1) { FullMode = BoundedChannelFullMode.DropOldest, SingleReader = true });
    private readonly ITimer _prober;
    private readonly Task _raising;
    private IReadOnlyList<SkakelDiscoveredServer> _published = [];
    private bool _wanted;
    // Counts the probes sent, so an entry knows how many it answered; and when the last one went out.
    private long _probes;
    private DateTimeOffset? _probedAt;

    /// <summary>A browser for the servers of the given apps. Call <see cref="Start"/> to begin.</summary>
    /// <param name="port">The app's port number: servers answer probes on UDP at the number their HTTPS listens on.</param>
    /// <param name="appIds">The app ids whose servers this app can use. Answers from other apps are dropped. Null keeps every app's.</param>
    /// <param name="options">Logging and time.</param>
    public SkakelBrowser(int port, IEnumerable<string>? appIds = null, SkakelClientOptions? options = null)
        : this(Udp(port is >= 1 and <= 65535 ? port : throw new ArgumentOutOfRangeException(nameof(port), port, "A port is 1 to 65535.")), appIds, options)
    {
    }

    internal SkakelBrowser(IBrowseControl control, IEnumerable<string>? appIds, SkakelClientOptions? options, TimeSpan? probeEvery = null)
    {
        options ??= new SkakelClientOptions();
        _time = options.Time;
        _logger = options.Loggers.CreateLogger<SkakelBrowser>();
        _control = control;
        _appIds = appIds is null ? null : [.. appIds];
        _probeEvery = probeEvery ?? SkakelDiscovery.ProbeInterval;
        _raising = Task.Run(RaiseInOrderAsync);
        _prober = _time.CreateTimer(_ => TickSafely(), null, _probeEvery, _probeEvery);
    }

    /// <summary>Raised when a server appears, changes or goes away. One list at a time, in the order the changes happened; a slow handler gets the latest list, not every one in between.</summary>
    public event Func<IReadOnlyList<SkakelDiscoveredServer>, Task>? Changed;

    /// <summary>An entry that missed three probes in a row, and a little more, is gone: 35 seconds.</summary>
    internal TimeSpan EntryLifetime => _probeEvery * 3.5;

    /// <summary>
    /// One entry per fingerprint, sorted by name: the address that answered first on the best network,
    /// with every other address that answered with the same fingerprint in
    /// <see cref="SkakelDiscoveredServer.OtherEndpoints"/>.
    /// </summary>
    public IReadOnlyList<SkakelDiscoveredServer> Servers
    {
        get
        {
            lock (_gate)
            {
                return Snapshot();
            }
        }
    }

    /// <summary>Every address and port that answered, one entry each, the best network and the longest standing first. What a link looks through to follow its server.</summary>
    internal IReadOnlyList<SkakelDiscoveredServer> Entries
    {
        get
        {
            lock (_gate)
            {
                return [.. Ordered(_seen.Values).Select(s => s.Server)];
            }
        }
    }

    /// <summary>True while probes go out.</summary>
    public bool IsBrowsing => _control.IsBrowsing;

    /// <summary>Starts listening and sends the first probe at once.</summary>
    public void Start()
    {
        lock (_browseLock)
        {
            _wanted = true;
            if (!_control.IsBrowsing)
            {
                _control.StartBrowse(Answered);
                ProbeNow();
            }
        }
    }

    /// <summary>Stops probing and empties the list.</summary>
    public void Stop()
    {
        lock (_browseLock)
        {
            _wanted = false;
            if (_control.IsBrowsing)
            {
                _control.StopBrowse();
            }
        }

        lock (_gate)
        {
            _seen.Clear();
            _probedAt = null;
            Publish();
        }
    }

    /// <summary>Stops, and waits for the last list to be raised.</summary>
    public void Dispose()
    {
        Stop();
        _prober.Dispose();
        (_control as IDisposable)?.Dispose();
        _changes.Writer.TryComplete();
        _raising.GetAwaiter().GetResult();
    }

    /// <summary>Reads an answer with the protocol's limits, or null for anything else.</summary>
    /// <param name="answer">The datagram.</param>
    /// <param name="from">Where it came from, which is the address to reach the server on.</param>
    internal static SkakelDiscoveredServer? Read(ReadOnlySpan<byte> answer, IPAddress from)
    {
        if (!SkakelDiscovery.TryParseAnswer(answer, out var parsed))
        {
            return null;
        }

        var address = from.IsIPv4MappedToIPv6 ? from.MapToIPv4() : from;
        var name = parsed.Name.Length > 0 ? parsed.Name : address.ToString();
        return new SkakelDiscoveredServer(name, address, parsed.Port, parsed.Fingerprint, parsed.App, parsed.Versions);
    }

    /// <summary>Keeps the entries of servers with these pins from being pushed out to make room, until disposed. A link does this while it lives.</summary>
    internal IDisposable Protect(Func<SkakelPins> pins)
    {
        lock (_gate)
        {
            _protected.Add(pins);
        }

        return new Unprotect(this, pins);
    }

    /// <summary>An answer from the network: taken only within a few seconds of a probe, as answers to it.</summary>
    internal void Answered(SkakelDiscoveredServer server, int rank)
    {
        lock (_gate)
        {
            if (_probedAt is not { } probedAt || _time.GetUtcNow() - probedAt > AnswerWindow)
            {
                return;
            }
        }

        Add(server, rank);
    }

    /// <summary>
    /// Keeps or refreshes an entry. When one address already holds its share, one of its entries goes to
    /// make room. When the whole list is full, one goes from the address holding the most, so a flood from
    /// one address pushes out its own entries and not other servers'. The one that goes is the one that
    /// answered the fewest probes, then the stalest, and never one a running link has pinned; when only
    /// those are left, the new answer is dropped instead. Another app's server takes no room at all.
    /// </summary>
    internal void Add(SkakelDiscoveredServer server, int rank)
    {
        if (_appIds is not null && !_appIds.Contains(server.App.Id))
        {
            return;
        }

        var key = new EntryKey(server.Fingerprint, server.Address, server.Port);
        lock (_gate)
        {
            var now = _time.GetUtcNow();
            if (_seen.TryGetValue(key, out var seen))
            {
                var answered = seen.LastProbe == _probes ? seen.Answers : seen.Answers + 1;
                _seen[key] = seen with { Server = server, Rank = rank, LastSeen = now, Answers = answered, LastProbe = _probes };
            }
            else if (MakeRoom(server.Address))
            {
                _seen[key] = new Seen(server, rank, now, now, 1, _probes);
            }
            else
            {
                return;
            }

            Publish();
        }
    }

    /// <summary>Drops the entries that stopped answering.</summary>
    internal void Sweep()
    {
        lock (_gate)
        {
            var now = _time.GetUtcNow();
            var gone = _seen.Where(e => e.Value.LastSeen + EntryLifetime <= now).Select(e => e.Key).ToList();
            foreach (var key in gone)
            {
                _seen.Remove(key);
            }

            if (gone.Count > 0)
            {
                Publish();
            }
        }
    }

    /// <summary>The probe targets: the limited broadcast address and each IPv4 network's own.</summary>
    internal static IBrowseControl Udp(int port, IReadOnlyList<IPEndPoint>? targets = null) => new UdpBrowse(port, targets);

    /// <summary>Best network first, then the longest standing, so a newcomer does not take an older entry's place.</summary>
    private static IOrderedEnumerable<Seen> Ordered(IEnumerable<Seen> entries) =>
        entries.OrderBy(s => s.Rank).ThenBy(s => s.FirstSeen).ThenBy(s => s.Server.Address.ToString(), StringComparer.Ordinal).ThenBy(s => s.Server.Port);

    /// <summary>
    /// Makes room for an entry from <paramref name="address"/>, with the gate held: false when every entry
    /// that could go is protected.
    /// </summary>
    private bool MakeRoom(IPAddress address)
    {
        var candidates = _seen.Where(e => !IsProtected(e.Key.Fingerprint)).ToList();
        IEnumerable<KeyValuePair<EntryKey, Seen>> from;
        if (_seen.Count(e => e.Key.Address.Equals(address)) >= SkakelDiscovery.MaxEntriesPerAddress)
        {
            from = candidates.Where(e => e.Key.Address.Equals(address));
        }
        else if (_seen.Count >= SkakelDiscovery.MaxEntries)
        {
            from = candidates.GroupBy(e => e.Key.Address).MaxBy(g => g.Count()) ?? Enumerable.Empty<KeyValuePair<EntryKey, Seen>>();
        }
        else
        {
            return true;
        }

        var victim = from.OrderBy(e => e.Value.Answers).ThenBy(e => e.Value.LastSeen).Select(e => (KeyValuePair<EntryKey, Seen>?)e).FirstOrDefault();
        if (victim is not { } evict)
        {
            return false;
        }

        _seen.Remove(evict.Key);
        return true;
    }

    /// <summary>Whether a running link has pinned this fingerprint, with the gate held.</summary>
    private bool IsProtected(string fingerprint) => _protected.Any(pins => pins().Trusts(fingerprint));

    /// <summary>Sends a probe, and takes answers for the next few seconds. With the browse lock held.</summary>
    private void ProbeNow()
    {
        lock (_gate)
        {
            _probes++;
            _probedAt = _time.GetUtcNow();
        }

        _control.Probe();
    }

    /// <summary>
    /// Drops what stopped answering, then probes again. Under the same lock as Start and Stop, so a stop
    /// cannot be undone by a tick that was already on its way.
    /// </summary>
    private void Tick()
    {
        Sweep();
        lock (_browseLock)
        {
            if (_wanted && _control.IsBrowsing)
            {
                ProbeNow();
            }
        }
    }

    /// <summary>The timer's callback. An exception that leaves a timer thread ends the process, so nothing leaves.</summary>
    private void TickSafely()
    {
        try
        {
            Tick();
        }
        catch (Exception ex)
        {
            LogTickFailed(ex);
        }
    }

    private IReadOnlyList<SkakelDiscoveredServer> Snapshot() =>
        [.. _seen.Values
            .GroupBy(s => s.Server.Fingerprint)
            .Select(g =>
            {
                var ordered = Ordered(g).ToList();
                return ordered[0].Server with { OtherEndpoints = [.. ordered.Skip(1).Select(s => new IPEndPoint(s.Server.Address, s.Server.Port))] };
            })
            .OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(s => s.Fingerprint, StringComparer.Ordinal)];

    /// <summary>Queues the current list when it differs from the last one queued, with the gate held, so lists leave in the order the changes happened.</summary>
    private void Publish()
    {
        var snapshot = Snapshot();
        if (!snapshot.SequenceEqual(_published))
        {
            _published = snapshot;
            _changes.Writer.TryWrite(snapshot);
        }
    }

    private async Task RaiseInOrderAsync()
    {
        await foreach (var servers in _changes.Reader.ReadAllAsync())
        {
            await Changed.RaiseAsync(servers, _logger);
        }
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "Could not sweep the list of servers or send a probe")]
    private partial void LogTickFailed(Exception exception);

    /// <summary>One answer: the fingerprint tells servers apart, the address and port tell the copies of one apart.</summary>
    private readonly record struct EntryKey(string Fingerprint, IPAddress Address, int Port);

    /// <summary>An entry, when it first and last answered, and how many probes it answered (up to the one numbered <see cref="LastProbe"/>).</summary>
    private sealed record Seen(SkakelDiscoveredServer Server, int Rank, DateTimeOffset FirstSeen, DateTimeOffset LastSeen, long Answers, long LastProbe);

    private sealed class Unprotect(SkakelBrowser browser, Func<SkakelPins> pins) : IDisposable
    {
        public void Dispose()
        {
            lock (browser._gate)
            {
                browser._protected.Remove(pins);
            }
        }
    }

    /// <summary>Starting and stopping the browse and sending probes, so a test can stand in for the network.</summary>
    internal interface IBrowseControl
    {
        bool IsBrowsing { get; }

        /// <summary>Starts listening for answers. <paramref name="found"/> gets each server and its rank (0 for a physical network).</summary>
        void StartBrowse(Action<SkakelDiscoveredServer, int> found);

        void StopBrowse();

        void Probe();
    }

    private sealed class UdpBrowse(int port, IReadOnlyList<IPEndPoint>? targets) : IBrowseControl, IDisposable
    {
        /// <summary>How long the list of physical networks is reused before it is read again.</summary>
        private static readonly TimeSpan NetworksFor = TimeSpan.FromSeconds(10);

        private readonly Lock _lock = new();
        private Socket? _socket;
        private CancellationTokenSource? _stop;
        private IReadOnlyList<UnicastIPAddressInformation> _physical = [];
        private long _physicalUntil = long.MinValue;

        public bool IsBrowsing
        {
            get
            {
                lock (_lock)
                {
                    return _socket is not null;
                }
            }
        }

        public void StartBrowse(Action<SkakelDiscoveredServer, int> found)
        {
            lock (_lock)
            {
                var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp) { EnableBroadcast = true };
                try
                {
                    socket.Bind(new IPEndPoint(IPAddress.Any, 0));
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }

                _socket = socket;
                _stop = new CancellationTokenSource();
                _ = ListenAsync(socket, found, Rank, _stop.Token);
            }
        }

        public void StopBrowse()
        {
            lock (_lock)
            {
                _stop?.Cancel();
                _stop?.Dispose();
                _socket?.Dispose();
                _stop = null;
                _socket = null;
            }
        }

        public void Dispose() => StopBrowse();

        public void Probe()
        {
            Socket? socket;
            lock (_lock)
            {
                socket = _socket;
            }

            var probe = SkakelDiscovery.CreateProbe();
            foreach (var target in targets ?? BroadcastTargets(port))
            {
                try
                {
                    socket?.SendTo(probe, target);
                }
                catch (SocketException)
                {
                    // That network is down or refuses broadcasts; the others still get the probe.
                }
                catch (ObjectDisposedException)
                {
                    // Stopped meanwhile.
                    return;
                }
            }
        }

        private static async Task ListenAsync(Socket socket, Action<SkakelDiscoveredServer, int> found, Func<IPAddress, int> rank, CancellationToken cancellationToken)
        {
            var buffer = new byte[2048];
            var anyone = new IPEndPoint(IPAddress.Any, 0);
            while (!cancellationToken.IsCancellationRequested)
            {
                SocketReceiveFromResult received;
                try
                {
                    received = await socket.ReceiveFromAsync(buffer, SocketFlags.None, anyone, cancellationToken);
                }
                catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException)
                {
                    return;
                }
                catch (SocketException)
                {
                    // Windows reports a probe nobody received on the next receive. Keep listening.
                    continue;
                }

                var from = ((IPEndPoint)received.RemoteEndPoint).Address;
                if (Read(buffer.AsSpan(0, received.ReceivedBytes), from) is { } server)
                {
                    found(server, rank(from));
                }
            }
        }

        /// <summary>
        /// The limited broadcast address and each IPv4 network's own broadcast address. On a machine with
        /// several networks the limited one only leaves through one of them.
        /// </summary>
        private static IEnumerable<IPEndPoint> BroadcastTargets(int port) =>
            LocalNetworks()
                .Where(u => !u.IPv4Mask.Equals(IPAddress.Broadcast))
                .Select(u =>
                {
                    var address = u.Address.GetAddressBytes();
                    var mask = u.IPv4Mask.GetAddressBytes();
                    return new IPAddress([.. address.Select((b, i) => (byte)(b | ~mask[i]))]);
                })
                .Prepend(IPAddress.Broadcast)
                .Distinct()
                .Select(address => new IPEndPoint(address, port));

        private static IEnumerable<UnicastIPAddressInformation> LocalNetworks(Func<NetworkInterface, bool>? where = null) =>
            NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .Where(where ?? (_ => true))
                .SelectMany(n => n.GetIPProperties().UnicastAddresses)
                .Where(u => u.Address.AddressFamily == AddressFamily.InterNetwork);

        /// <summary>
        /// Prefers an address on a wired or wireless network over one on a virtual network, such as a
        /// Hyper-V switch or Docker's bridge, when a server answers on both. The networks are read at most
        /// once every ten seconds, not for every answer.
        /// </summary>
        private int Rank(IPAddress address)
        {
            IReadOnlyList<UnicastIPAddressInformation> physical;
            lock (_lock)
            {
                if (Environment.TickCount64 >= _physicalUntil)
                {
                    _physical = [.. LocalNetworks(n =>
                        n.NetworkInterfaceType is NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211
                        && !n.Description.Contains("Virtual", StringComparison.OrdinalIgnoreCase)
                        && !n.Description.Contains("Hyper-V", StringComparison.OrdinalIgnoreCase))];
                    _physicalUntil = Environment.TickCount64 + (long)NetworksFor.TotalMilliseconds;
                }

                physical = _physical;
            }

            return physical.Any(u => SameSubnet(address, u)) ? 0 : 1;
        }

        private static bool SameSubnet(IPAddress address, UnicastIPAddressInformation local)
        {
            var a = address.GetAddressBytes();
            var b = local.Address.GetAddressBytes();
            var mask = local.IPv4Mask.GetAddressBytes();
            return a.Length == 4 && Enumerable.Range(0, 4).All(i => (a[i] & mask[i]) == (b[i] & mask[i]));
        }
    }
}
