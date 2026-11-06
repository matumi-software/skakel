using System.Text;
using Skakel.Protocol;

namespace Skakel.Discovery.Tests;

/// <summary>
/// Pins the bytes the Rust crate <c>skakel-discovery</c> pins too, with the same vectors, so the two
/// languages cannot drift apart without one of the suites failing.
/// </summary>
public sealed class WireVectorTests
{
    private static readonly string Fingerprint = string.Join(':', Enumerable.Repeat("EF", 32));

    private static string Text(byte[] datagram) => Encoding.UTF8.GetString(datagram);

    private static string Rune(int codePoint) => char.ConvertFromUtf32(codePoint);

    [Fact]
    public void CreateAnswer_writes_the_bytes_the_rust_side_pins()
    {
        var answer = SkakelDiscovery.CreateAnswer(new DiscoveryAnswer("pi-lab", 5240, Fingerprint, new SkakelApp("koppel", "0.1.1"), [1]));

        Text(answer).Should().Be("SKAKEL-SERVER/1\n{\"name\":\"pi-lab\",\"port\":5240,\"fingerprint\":\"" + Fingerprint + "\",\"app\":{\"id\":\"koppel\",\"version\":\"0.1.1\"},\"versions\":[1]}");
    }

    [Fact]
    public void CreateAnswer_cleans_normalises_and_escapes_the_way_the_rust_side_pins()
    {
        var name = "  pi" + Rune(0x202E) + "lab " + Rune(0x1F600) + "\n";
        var given = new DiscoveryAnswer(name, 65535, Fingerprint.ToLowerInvariant().Replace(":", "", StringComparison.Ordinal), new SkakelApp("a-1", "1.0" + Rune(0x200B)), [1, 2, 3, 4, 5, 6, 7, 8]);

        Text(SkakelDiscovery.CreateAnswer(given)).Should().Be("SKAKEL-SERVER/1\n{\"name\":\"pilab \\uD83D\\uDE00\",\"port\":65535,\"fingerprint\":\"" + Fingerprint + "\",\"app\":{\"id\":\"a-1\",\"version\":\"1.0\"},\"versions\":[1,2,3,4,5,6,7,8]}");
    }

    [Theory]
    [InlineData(0x61, 63, 322)]
    [InlineData(0xE9, 63, 417)]
    [InlineData(0x1F600, 7, 503)]
    [InlineData(0x22, 63, 417)]
    public void CreateAnswer_cuts_a_long_name_where_the_rust_side_does(int codePoint, int nameCharacters, int bytes)
    {
        var text = string.Concat(Enumerable.Repeat(Rune(codePoint), 200));

        var answer = SkakelDiscovery.CreateAnswer(new DiscoveryAnswer(text, 5240, Fingerprint, new SkakelApp(new string('z', 32), text), [1]));

        answer.Length.Should().Be(bytes);
        SkakelDiscovery.TryParseAnswer(answer, out var parsed).Should().BeTrue();
        parsed!.Name.EnumerateRunes().Count().Should().Be(nameCharacters);
    }

    [Theory]
    [InlineData(0x1F600, "\\uD83D\\uDE00")]
    [InlineData(0xA0, "\\u00A0")]
    [InlineData(0xE000, "\\uE000")]
    [InlineData(0xE9, "é")]
    [InlineData(0x4E2D, "中")]
    public void CreateAnswer_escapes_the_way_the_rust_side_does(int codePoint, string written)
    {
        // Between other text, so nothing is trimmed.
        var answer = SkakelDiscovery.CreateAnswer(new DiscoveryAnswer("x" + Rune(codePoint) + "x", 5240, Fingerprint, new SkakelApp("koppel", "1"), [1]));

        Text(answer).Should().Contain("\"name\":\"x" + written + "x\"");
    }

    [Fact]
    public void CreateAnswer_leaves_the_characters_the_relaxed_encoder_leaves()
    {
        var answer = SkakelDiscovery.CreateAnswer(new DiscoveryAnswer("x<>&+x", 5240, Fingerprint, new SkakelApp("koppel", "1"), [1]));

        Text(answer).Should().Contain("\"name\":\"x<>&+x\"");
    }
}
