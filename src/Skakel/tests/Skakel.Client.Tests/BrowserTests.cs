using System.Globalization;
using System.Net;
using System.Text;
using Skakel.Protocol;

namespace Skakel.Client.Tests;

/// <summary>Discovery: reading answers with the protocol's limits, the bounded list, and the real exchange.</summary>
public sealed class BrowserTests
{
    private static readonly string Fingerprint = string.Join(':', Enumerable.Repeat("AB", 32));

    [Fact]
    public void Read_takes_an_answer_from_the_server_and_its_address()
    {
        var answer = SkakelDiscovery.CreateAnswer(new DiscoveryAnswer("pi-lab", 5240, Fingerprint.Replace(":", "", StringComparison.Ordinal), new SkakelApp("koppel", "0.1.1"), [1]));

        var server = SkakelBrowser.Read(answer, IPAddress.Parse("::ffff:192.168.1.20"));

        server.Should().NotBeNull();
        server!.Name.Should().Be("pi-lab");
        server.Address.Should().Be(IPAddress.Parse("192.168.1.20"));
        server.Fingerprint.Should().Be(Fingerprint);
        server.Url.Should().Be(new Uri("https://192.168.1.20:5240/"));
        server.Version.Should().Be(1);
    }

    [Theory]
    [InlineData("{\"name\":\"x\",\"port\":5240,\"fingerprint\":\"AB\",\"app\":{\"id\":\"koppel\",\"version\":\"1\"},\"versions\":[1]}")]
    [InlineData("{\"name\":\"x\",\"port\":5240,\"fingerprint\":\"FP\",\"app\":{\"id\":\"Koppel\",\"version\":\"1\"},\"versions\":[1]}")]
    [InlineData("{\"name\":\"x\",\"port\":5240,\"fingerprint\":\"FP\",\"app\":{\"id\":\"koppel\",\"version\":\"1\"},\"versions\":[1,2,3,4,5,6,7,8,9]}")]
    [InlineData("{\"name\":\"x\",\"port\":0,\"fingerprint\":\"FP\",\"app\":{\"id\":\"koppel\",\"version\":\"1\"},\"versions\":[1]}")]
    [InlineData("not json")]
    public void Read_drops_an_answer_outside_the_limits(string json)
    {
        var datagram = Encoding.UTF8.GetBytes("SKAKEL-SERVER/1\n" + json.Replace("FP", Fingerprint, StringComparison.Ordinal));

        SkakelBrowser.Read(datagram, IPAddress.Loopback).Should().BeNull();
    }

    [Fact]
    public void Read_drops_a_name_over_63_characters()
    {
        var json = $"{{\"name\":\"{new string('n', 64)}\",\"port\":5240,\"fingerprint\":\"{Fingerprint}\",\"app\":{{\"id\":\"koppel\",\"version\":\"1\"}},\"versions\":[1]}}";

        SkakelBrowser.Read(Encoding.UTF8.GetBytes("SKAKEL-SERVER/1\n" + json), IPAddress.Loopback).Should().BeNull();
    }

    [Fact]
    public void Add_keeps_at_most_8_from_one_address_dropping_its_stalest()
    {
        var time = new ManualTimeProvider();
        using var browser = Browser(time);
        for (var i = 0; i < 9; i++)
        {
            browser.Add(Server(i, "10.0.0.1"), 0);
            time.Advance(TimeSpan.FromSeconds(1));
        }

        browser.Servers.Should().HaveCount(8);
        browser.Servers.Select(s => s.Name).Should().NotContain("server-00", "it was the stalest");
    }

    [Fact]
    public void Add_keeps_at_most_64_dropping_from_the_address_that_holds_the_most()
    {
        var time = new ManualTimeProvider();
        using var browser = Browser(time);
        for (var i = 0; i < 64; i++)
        {
            browser.Add(Server(i, $"10.0.{i / 8}.1"), 0);
            // Under the ten seconds to the next probe, which would sweep.
            time.Advance(TimeSpan.FromMilliseconds(100));
        }

        browser.Add(Server(100, "10.0.9.9"), 0);

        browser.Servers.Should().HaveCount(64);
        browser.Servers.Select(s => s.Name).Should().Contain("server-100").And.NotContain("server-00");
    }

    [Fact]
    public void Add_drops_servers_of_other_apps()
    {
        using var browser = Browser(new ManualTimeProvider());

        browser.Add(Server(1, "10.0.0.1") with { App = new SkakelApp("other", "1") }, 0);
        browser.Add(Server(2, "10.0.0.1"), 0);

        browser.Servers.Should().ContainSingle().Which.Name.Should().Be("server-02");
    }

    [Fact]
    public void Sweep_drops_an_entry_after_three_missed_probes()
    {
        var time = new ManualTimeProvider();
        using var browser = Browser(time);
        browser.Add(Server(1, "10.0.0.1"), 0);

        time.Advance(TimeSpan.FromSeconds(34));
        browser.Sweep();
        browser.Servers.Should().HaveCount(1);

        time.Advance(TimeSpan.FromSeconds(1));
        browser.Sweep();
        browser.Servers.Should().BeEmpty();
    }

    [Fact]
    public async Task Changed_is_raised_only_when_the_list_changed()
    {
        using var browser = Browser(new ManualTimeProvider());
        var lists = new Recorder<IReadOnlyList<SkakelDiscoveredServer>>();
        browser.Changed += lists.Record;

        browser.Add(Server(1, "10.0.0.1"), 0);
        await lists.WaitAsync(l => l.Count == 1);
        browser.Add(Server(1, "10.0.0.1"), 0);
        browser.Add(Server(1, "10.0.0.1"), 0);
        browser.Add(Server(2, "10.0.0.1"), 0);
        await lists.WaitAsync(l => l.Count == 2);

        lists.Seen.Should().HaveCount(2, "the same answer again is no change");
    }

    [Fact]
    public async Task Changed_gives_a_slow_listener_the_latest_list()
    {
        using var browser = Browser(new ManualTimeProvider());
        var release = new TaskCompletionSource();
        var lists = new Recorder<IReadOnlyList<SkakelDiscoveredServer>>();
        browser.Changed += async list =>
        {
            await lists.Record(list);
            await release.Task;
        };

        browser.Add(Server(1, "10.0.0.1"), 0);
        await lists.WaitAsync(l => l.Count == 1);
        for (var i = 2; i <= 5; i++)
        {
            browser.Add(Server(i, "10.0.0.1"), 0);
        }

        release.SetResult();
        await lists.WaitAsync(l => l.Count == 5);

        lists.Seen.Select(l => l.Count).Should().Equal(1, 5);
    }

    [Fact]
    public async Task A_probe_finds_a_real_server_by_its_discovery_answer()
    {
        var udp = Ports.FreeUdp();
        await using var host = await SkakelHost.StartAsync(discoveryPort: udp);
        using var browser = new SkakelBrowser(SkakelBrowser.Udp(udp, [new IPEndPoint(IPAddress.Loopback, udp)]), ["test-app"], null);
        var lists = new Recorder<IReadOnlyList<SkakelDiscoveredServer>>();
        browser.Changed += lists.Record;

        browser.Start();

        var found = (await lists.WaitAsync(l => l.Count == 1)).Single();
        found.Should().Be(new SkakelDiscoveredServer("bench", IPAddress.Loopback, host.Port, host.Keys.Fingerprint, new SkakelApp("test-app", "1.2.3"), [1]));
        browser.Stop();
        browser.Servers.Should().BeEmpty();
    }

    private static SkakelBrowser Browser(TimeProvider time) =>
        new(new NoNetwork(), ["koppel"], new SkakelClientOptions { TimeProvider = time });

    private static SkakelDiscoveredServer Server(int n, string address)
    {
        var hex = n.ToString("X2", CultureInfo.InvariantCulture);
        return new SkakelDiscoveredServer($"server-{n:D2}", IPAddress.Parse(address), 5240, string.Join(':', Enumerable.Repeat(hex, 32)), new SkakelApp("koppel", "0.1.1"), [1]);
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
