using System.Net;
using Skakel.Protocol;
using Skakel.Server;

namespace Skakel.Client.Tests;

/// <summary>Following a server that moved: only when nothing answers at the saved address, and only to one that proves its certificate.</summary>
public sealed class MoveTests
{
    private static readonly SkakelApp App = new("test-app", "1.2.3");

    [Fact]
    public async Task A_link_follows_its_server_to_another_port()
    {
        var store = new InMemorySkakelStore();
        var first = await SkakelHost.StartAsync(store);
        var credentials = await first.RegisterAsync();
        var pins = first.Pins;
        using var browser = new SkakelBrowser(new NoNetwork(), ["test-app"], null);
        await using var link = new SkakelLink(first.Address, pins, credentials, new SkakelClientOptions { Browser = browser });
        var statuses = LinkTests.Record(link);
        var moves = new Recorder<Uri>();
        link.AddressChanged += moves.Record;
        link.Start();
        await statuses.WaitAsync(s => s.State == SkakelLinkState.Connected);

        await first.DisposeAsync();
        await statuses.WaitAsync(s => s.Failure?.Kind == SkakelFailureKind.Unreachable);
        await using var second = await SkakelHost.StartAsync(store);
        second.Keys.Fingerprint.Should().Be(pins.Fingerprint, "the same state is the same certificate");
        browser.Add(new SkakelDiscoveredServer("bench", IPAddress.Loopback, second.Port, pins.Fingerprint, App, [1]), 0);

        (await moves.WaitAsync(_ => true)).Should().Be(second.Address);
        link.Address.Should().Be(second.Address);
        await statuses.WaitAsync(_ => statuses.Seen.Count(s => s.State == SkakelLinkState.Connected) == 2);
    }

    [Fact]
    public async Task A_link_does_not_follow_an_answer_that_copied_the_fingerprint()
    {
        var first = await SkakelHost.StartAsync();
        var credentials = await first.RegisterAsync();
        var saved = first.Address;
        var pins = first.Pins;
        await using var decoy = await SkakelHost.StartAsync();
        using var browser = new SkakelBrowser(new NoNetwork(), ["test-app"], null);
        await using var link = new SkakelLink(saved, pins, credentials, new SkakelClientOptions { Browser = browser });
        var statuses = LinkTests.Record(link);
        var moves = new Recorder<Uri>();
        link.AddressChanged += moves.Record;
        link.Start();
        await statuses.WaitAsync(s => s.State == SkakelLinkState.Connected);
        await first.DisposeAsync();
        await statuses.WaitAsync(s => s.Failure?.Kind == SkakelFailureKind.Unreachable);
        // Handlers run one at a time in the order they subscribed: once this one sees the list, the link has looked at it.
        var heard = new Recorder<IReadOnlyList<SkakelDiscoveredServer>>();
        browser.Changed += heard.Record;

        browser.Add(new SkakelDiscoveredServer("bench", IPAddress.Loopback, decoy.Port, pins.Fingerprint, App, [1]), 0);
        await heard.WaitAsync(l => l.Count == 1);
        // The search runs in the background; wait for it to give up.
        await link.Following;

        moves.Seen.Should().BeEmpty();
        link.Address.Should().Be(saved);
    }

    [Fact]
    public async Task A_link_follows_its_server_past_an_address_that_copied_the_fingerprint()
    {
        var store = new InMemorySkakelStore();
        var first = await SkakelHost.StartAsync(store);
        var credentials = await first.RegisterAsync();
        var pins = first.Pins;
        await using var decoy = await SkakelHost.StartAsync();
        using var browser = new SkakelBrowser(new NoNetwork(), ["test-app"], null);
        await using var link = new SkakelLink(first.Address, pins, credentials, new SkakelClientOptions { Browser = browser });
        var statuses = LinkTests.Record(link);
        var moves = new Recorder<Uri>();
        link.AddressChanged += moves.Record;
        link.Start();
        await statuses.WaitAsync(s => s.State == SkakelLinkState.Connected);
        await first.DisposeAsync();
        await statuses.WaitAsync(s => s.Failure?.Kind == SkakelFailureKind.Unreachable);

        // The copy answers first, so the list shows it; the real server is still among the candidates.
        browser.Add(new SkakelDiscoveredServer("bench", IPAddress.Loopback, decoy.Port, pins.Fingerprint, App, [1]), 0);
        await using var second = await SkakelHost.StartAsync(store);
        browser.Add(new SkakelDiscoveredServer("bench", IPAddress.Loopback, second.Port, pins.Fingerprint, App, [1]), 0);

        browser.Servers.Should().ContainSingle().Which.Port.Should().Be(decoy.Port);
        (await moves.WaitAsync(_ => true)).Should().Be(second.Address);
    }

    [Fact]
    public async Task A_slow_search_does_not_hold_up_the_browsers_other_listeners()
    {
        var first = await SkakelHost.StartAsync();
        var credentials = await first.RegisterAsync();
        var pins = first.Pins;
        // Takes the connection and never answers the handshake, so a proof runs its full five seconds.
        using var silent = new Listener();
        using var browser = new SkakelBrowser(new NoNetwork(), ["test-app"], null);
        await using var link = new SkakelLink(first.Address, pins, credentials, new SkakelClientOptions { Browser = browser });
        var statuses = LinkTests.Record(link);
        link.Start();
        await statuses.WaitAsync(s => s.State == SkakelLinkState.Connected);
        await first.DisposeAsync();
        await statuses.WaitAsync(s => s.Failure?.Kind == SkakelFailureKind.Unreachable);
        var heard = new Recorder<IReadOnlyList<SkakelDiscoveredServer>>();
        browser.Changed += heard.Record;

        browser.Add(new SkakelDiscoveredServer("bench", IPAddress.Loopback, silent.Port, pins.Fingerprint, App, [1]), 0);
        browser.Add(new SkakelDiscoveredServer("other", IPAddress.Loopback, 1, string.Join(':', Enumerable.Repeat("EF", 32)), App, [1]), 0);

        await heard.WaitAsync(l => l.Count == 2, TimeSpan.FromSeconds(2));
        link.Following.IsCompleted.Should().BeFalse("the proof is still waiting on the silent address");
    }

    [Fact]
    public void Candidates_takes_every_trusted_address_up_to_eight_and_puts_failed_ones_last()
    {
        var pins = new SkakelPins(string.Join(':', Enumerable.Repeat("AB", 32)));
        var saved = new Uri("https://10.0.0.1:5240/");
        var servers = Enumerable.Range(2, 10).Select(i => new SkakelDiscoveredServer("pi-lab", IPAddress.Parse($"10.0.0.{i}"), 5240, pins.Fingerprint, App, [1])).ToList();
        var failed = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        var candidates = ServerMoves.Candidates(saved, pins, servers, [], failedAt: a => a is "10.0.0.2:5240" or "10.0.0.3:5240" ? failed : null);

        candidates.Should().HaveCount(ServerMoves.MaxProofs);
        candidates.Select(c => c.Host).Should().Equal("10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8", "10.0.0.9", "10.0.0.10", "10.0.0.11");
    }

    [Fact]
    public async Task FindAsync_tries_the_next_address_when_the_first_fails_its_proof()
    {
        var ct = TestContext.Current.CancellationToken;
        using var moves = new ServerMoves(new ManualTimeProvider(), Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);
        var pins = new SkakelPins(string.Join(':', Enumerable.Repeat("AB", 32)));
        IReadOnlyList<SkakelDiscoveredServer> servers =
        [
            new("copy", IPAddress.Parse("10.0.0.66"), 5240, pins.Fingerprint, App, [1]),
            new("pi-lab", IPAddress.Parse("10.0.0.5"), 5240, pins.Fingerprint, App, [1]),
        ];

        var to = await moves.FindAsync(new Uri("https://10.0.0.1:5240/"), pins, servers, url => Task.FromResult(url.Host == "10.0.0.5"), ct);

        to.Should().Be(new Uri("https://10.0.0.5:5240/"));
    }

    [Fact]
    public void Candidates_prefers_the_saved_host_and_skips_the_saved_address_others_and_held_off()
    {
        var pins = new SkakelPins(string.Join(':', Enumerable.Repeat("AB", 32)), string.Join(':', Enumerable.Repeat("CD", 32)));
        var saved = new Uri("https://pi-lab.local:5241/");
        SkakelDiscoveredServer At(string address, int port, string fingerprint) => new("pi-lab", IPAddress.Parse(address), port, fingerprint, App, [1]);
        var servers = new[]
        {
            At("10.0.0.9", 5240, pins.Fingerprint),
            At("10.0.0.7", 5240, pins.NextFingerprint!),
            At("10.0.0.7", 5241, pins.Fingerprint),
            At("10.0.0.8", 5240, string.Join(':', Enumerable.Repeat("EF", 32))),
            At("10.0.0.6", 5240, pins.Fingerprint),
        };

        var candidates = ServerMoves.Candidates(saved, pins, servers, [IPAddress.Parse("10.0.0.7")], heldOff: authority => authority == "10.0.0.6:5240");

        candidates.Should().Equal(new Uri("https://pi-lab.local:5240/"), new Uri("https://10.0.0.9:5240/"));
    }

    [Fact]
    public async Task FindAsync_does_not_move_to_the_same_address_again_for_five_minutes()
    {
        var ct = TestContext.Current.CancellationToken;
        var time = new ManualTimeProvider();
        using var moves = new ServerMoves(time, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);
        var pins = new SkakelPins(string.Join(':', Enumerable.Repeat("AB", 32)));
        var saved = new Uri("https://10.0.0.1:5240/");
        IReadOnlyList<SkakelDiscoveredServer> servers = [new("pi-lab", IPAddress.Parse("10.0.0.2"), 5240, pins.Fingerprint, App, [1])];

        (await moves.FindAsync(saved, pins, servers, _ => Task.FromResult(true), ct)).Should().Be(new Uri("https://10.0.0.2:5240/"));
        time.Advance(TimeSpan.FromMinutes(4));
        (await moves.FindAsync(saved, pins, servers, _ => Task.FromResult(true), ct)).Should().BeNull();
        time.Advance(TimeSpan.FromMinutes(1));
        (await moves.FindAsync(saved, pins, servers, _ => Task.FromResult(true), ct)).Should().Be(new Uri("https://10.0.0.2:5240/"));
        IReadOnlyList<SkakelDiscoveredServer> elsewhere = [new("pi-lab", IPAddress.Parse("10.0.0.4"), 5240, pins.Fingerprint, App, [1])];
        (await moves.FindAsync(saved, pins, elsewhere, _ => Task.FromResult(false), ct)).Should().BeNull("it did not prove the certificate");
    }

    /// <summary>A network nothing answers on; the tests add answers themselves.</summary>
    private sealed class NoNetwork : SkakelBrowser.IBrowseControl
    {
        public bool IsBrowsing { get; private set; }

        public void StartBrowse(Action<SkakelDiscoveredServer, int> found) => IsBrowsing = true;

        public void StopBrowse() => IsBrowsing = false;

        public void Probe()
        {
        }
    }
}
