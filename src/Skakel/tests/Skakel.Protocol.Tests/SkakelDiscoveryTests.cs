using System.Text;
using System.Text.Json;

namespace Skakel.Protocol.Tests;

public sealed class SkakelDiscoveryTests
{
    private static readonly string Fingerprint = string.Join(':', Enumerable.Repeat("EF", 32));

    private static DiscoveryAnswer Answer(string name = "pi-lab", string version = "0.1.1", string appId = "koppel") =>
        new(name, 5240, Fingerprint, new SkakelApp(appId, version), [1]);

    [Fact]
    public void CreateProbe_is_the_probe_line_and_zero_padding_to_512_bytes()
    {
        var probe = SkakelDiscovery.CreateProbe();

        probe.Should().HaveCount(512);
        Encoding.ASCII.GetString(probe, 0, 18).Should().Be("SKAKEL-DISCOVER/1\n");
        probe.Skip(18).Should().OnlyContain(b => b == 0);
    }

    [Fact]
    public void IsProbe_wants_the_line_and_at_least_512_bytes()
    {
        SkakelDiscovery.IsProbe(SkakelDiscovery.CreateProbe()).Should().BeTrue();
        SkakelDiscovery.IsProbe([.. SkakelDiscovery.CreateProbe(), 0]).Should().BeTrue();
        SkakelDiscovery.IsProbe(SkakelDiscovery.CreateProbe().AsSpan(0, 511)).Should().BeFalse();
        var koppel = new byte[512];
        "KOPPEL-DISCOVER/1\n"u8.CopyTo(koppel);
        SkakelDiscovery.IsProbe(koppel).Should().BeFalse("version 0 probes are not answered");
    }

    [Fact]
    public void CreateAnswer_writes_the_answer_line_and_the_json_the_protocol_shows()
    {
        var answer = SkakelDiscovery.CreateAnswer(Answer());

        Encoding.UTF8.GetString(answer).Should().StartWith("SKAKEL-SERVER/1\n");
        var json = JsonDocument.Parse(answer.AsMemory(16)).RootElement;
        json.GetProperty("name").GetString().Should().Be("pi-lab");
        json.GetProperty("port").GetInt32().Should().Be(5240);
        json.GetProperty("fingerprint").GetString().Should().Be(Fingerprint);
        json.GetProperty("app").GetProperty("id").GetString().Should().Be("koppel");
        json.GetProperty("app").GetProperty("version").GetString().Should().Be("0.1.1");
        json.GetProperty("versions").EnumerateArray().Select(v => v.GetInt32()).Should().Equal(1);
    }

    [Theory]
    [InlineData("a")]
    [InlineData("é")]
    [InlineData("😀")]
    [InlineData("\"")]
    public void CreateAnswer_always_fits_in_a_probe(string character)
    {
        var name = string.Concat(Enumerable.Repeat(character, 200));
        var version = string.Concat(Enumerable.Repeat(character, 200));

        var answer = SkakelDiscovery.CreateAnswer(Answer(name, version, new string('z', 32)));

        answer.Length.Should().BeLessThanOrEqualTo(SkakelDiscovery.ProbeSize);
        SkakelDiscovery.TryParseAnswer(answer, out var parsed).Should().BeTrue();
        parsed!.Name.Length.Should().BeLessThanOrEqualTo(SkakelDiscovery.MaxNameLength);
    }

    [Fact]
    public void CreateAnswer_refuses_what_a_client_would_drop()
    {
        FluentActions.Invoking(() => SkakelDiscovery.CreateAnswer(Answer() with { Fingerprint = "AB" })).Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => SkakelDiscovery.CreateAnswer(Answer(appId: "Koppel"))).Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => SkakelDiscovery.CreateAnswer(Answer() with { Port = 0 })).Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => SkakelDiscovery.CreateAnswer(Answer() with { Versions = [] })).Should().Throw<ArgumentException>();
    }

    [Fact]
    public void TryParseAnswer_reads_what_CreateAnswer_wrote()
    {
        SkakelDiscovery.TryParseAnswer(SkakelDiscovery.CreateAnswer(Answer()), out var parsed).Should().BeTrue();

        parsed.Should().BeEquivalentTo(Answer());
    }

    [Theory]
    [InlineData("""{"name":"x","port":5240,"fingerprint":"AB","app":{"id":"koppel","version":"1"},"versions":[1]}""")]
    [InlineData("""{"name":"x","port":0,"fingerprint":"FP","app":{"id":"koppel","version":"1"},"versions":[1]}""")]
    [InlineData("""{"name":"x","port":5240,"fingerprint":"FP","app":{"id":"Koppel","version":"1"},"versions":[1]}""")]
    [InlineData("""{"name":"x","port":5240,"fingerprint":"FP","app":{"id":"koppel","version":"1"},"versions":[]}""")]
    [InlineData("""{"name":"x","port":5240,"fingerprint":"FP","app":{"id":"koppel","version":"1"},"versions":[1,2,3,4,5,6,7,8,9]}""")]
    [InlineData("""{"name":"x","port":5240,"fingerprint":"FP","versions":[1]}""")]
    [InlineData("""{"port":5240,"fingerprint":"FP","app":{"id":"koppel","version":"1"},"versions":[1]}""")]
    [InlineData("not json")]
    public void TryParseAnswer_drops_an_answer_outside_the_limits(string body)
    {
        var datagram = Encoding.UTF8.GetBytes("SKAKEL-SERVER/1\n" + body.Replace("FP", Fingerprint, StringComparison.Ordinal));

        SkakelDiscovery.TryParseAnswer(datagram, out _).Should().BeFalse();
    }

    [Fact]
    public void TryParseAnswer_drops_a_long_name_or_version_and_a_wrong_first_line()
    {
        var longName = JsonSerializer.Serialize(Answer(name: new string('n', 64)), SkakelJson.Options);
        var longVersion = JsonSerializer.Serialize(Answer(version: new string('v', 33)), SkakelJson.Options);

        SkakelDiscovery.TryParseAnswer(Encoding.UTF8.GetBytes("SKAKEL-SERVER/1\n" + longName), out _).Should().BeFalse();
        SkakelDiscovery.TryParseAnswer(Encoding.UTF8.GetBytes("SKAKEL-SERVER/1\n" + longVersion), out _).Should().BeFalse();
        SkakelDiscovery.TryParseAnswer(Encoding.UTF8.GetBytes("KOPPEL-SERVER/1\n" + JsonSerializer.Serialize(Answer(), SkakelJson.Options)), out _).Should().BeFalse();
    }
}
