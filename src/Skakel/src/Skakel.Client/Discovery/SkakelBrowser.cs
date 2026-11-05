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
/// can answer anything, so what it keeps is bounded by the limits in the protocol: at most 64 entries
/// and 8 from one address, fingerprints that are really fingerprints, short names, and entries that go
/// when they stop answering. Entries are told apart by fingerprint and address, so a server that copies
/// a name sits beside the real one instead of replacing it, and an app can warn about the two.
/// </summary>
/// <remarks>One browser serves every link of an app; pass it to each in <see cref="SkakelClientOptions.Browser"/>.</remarks>
public sealed partial class SkakelBrowser : IDisposable
{
    private readonly IBrowseControl _control;
    private readonly TimeSpan _probeEvery;
    private readonly HashSet<string>? _appIds;
    private readonly Dictionary<EntryKey, Seen> _seen = [];
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

    /// <summary>One entry per server, however many of its addresses answered, sorted by name.</summary>
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
                _control.StartBrowse(Add);
                _control.Probe();
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

    /// <summary>
    /// Keeps or refreshes an entry. When one address already holds its share, its stalest entry goes to
    /// make room. When the whole list is full, the stalest entry of the address holding the most goes,
    /// so a flood from one address pushes out its own entries and not other servers'. Another app's
    /// server takes no room at all.
    /// </summary>
    internal void Add(SkakelDiscoveredServer server, int rank)
    {
        if (_appIds is not null && !_appIds.Contains(server.App.Id))
        {
            return;
        }

        var key = new EntryKey(server.Fingerprint, server.Address);
        lock (_gate)
        {
            if (!_seen.ContainsKey(key))
            {
                if (_seen.Count(e => e.Key.Address.Equals(server.Address)) >= SkakelDiscovery.MaxEntriesPerAddress)
                {
                    EvictStalest(server.Address);
                }
                else if (_seen.Count >= SkakelDiscovery.MaxEntries)
                {
                    EvictStalest(_seen.GroupBy(e => e.Key.Address).MaxBy(g => g.Count())!.Key);
                }
            }

            _seen[key] = new Seen(server, rank, _time.GetUtcNow());
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

    /// <summary>Drops the entry from this address that answered longest ago, with the gate held.</summary>
    private void EvictStalest(IPAddress address)
    {
        var stalest = _seen.Where(e => e.Key.Address.Equals(address)).MinBy(e => e.Value.LastSeen).Key;
        _seen.Remove(stalest);
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
                _control.Probe();
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
            .Select(g => g.OrderBy(s => s.Rank).ThenByDescending(s => s.LastSeen).First().Server)
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

    /// <summary>One server at one address: the fingerprint tells servers apart, the address tells the copies of one server apart.</summary>
    private readonly record struct EntryKey(string Fingerprint, IPAddress Address);

    private sealed record Seen(SkakelDiscoveredServer Server, int Rank, DateTimeOffset LastSeen);

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
        private readonly Lock _lock = new();
        private Socket? _socket;
        private CancellationTokenSource? _stop;

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
                _ = ListenAsync(socket, found, _stop.Token);
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

        private static async Task ListenAsync(Socket socket, Action<SkakelDiscoveredServer, int> found, CancellationToken cancellationToken)
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
                    found(server, Rank(from));
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
        /// Hyper-V switch or Docker's bridge, when a server answers on both.
        /// </summary>
        private static int Rank(IPAddress address)
        {
            var physical = LocalNetworks(n =>
                n.NetworkInterfaceType is NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211
                && !n.Description.Contains("Virtual", StringComparison.OrdinalIgnoreCase)
                && !n.Description.Contains("Hyper-V", StringComparison.OrdinalIgnoreCase));
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
