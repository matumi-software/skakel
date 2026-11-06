using System.Text.Json;
using Skakel.Protocol;

namespace Skakel.Pairing.Tests;

/// <summary>
/// Pins the bytes the Rust crate <c>skakel-pairing</c> pins too, with the same vectors, so the two
/// languages cannot drift apart without one of the suites failing.
/// </summary>
public sealed class WireVectorTests
{
    private const string Fingerprint = "EF:8E:16:AF:C3:88:BF:8C:94:CB:98:9A:3F:6A:93:F9:3D:0B:30:60:33:87:79:CF:C0:A4:E6:A4:30:89:14:29";

    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);

    [Fact]
    public void Compute_gives_the_codes_the_rust_side_pins()
    {
        PairingCode.Compute(Fingerprint, "c", "s").Should().Be("749912");
        PairingCode.Compute(Fingerprint, "client-nonce", "server-nonce").Should().Be("904104");
        PairingCode.Compute(Fingerprint, "pad-41", "s").Should().Be("008456", "a code that starts with zeros keeps them");
    }

    [Fact]
    public void Commit_gives_the_hash_the_rust_side_pins()
    {
        PairingCode.Commit("client-nonce").Should().Be("A35525BDCB47F876099F1C74B3E19AB3EA4C8A7BF6FD2EAB6A3C35BE602551C6");
    }

    [Fact]
    public void The_json_bodies_are_the_ones_the_rust_side_pins()
    {
        JsonSerializer.Serialize(new PairOpenRequest("Anna PC", "AB"), Web).Should().Be("""{"clientName":"Anna PC","commitment":"AB"}""");
        JsonSerializer.Serialize(new PairRevealRequest("n"), Web).Should().Be("""{"clientNonce":"n"}""");
        JsonSerializer.Serialize(new PairPoll(PairStates.Waiting), Web).Should().Be("""{"state":"waiting","clientId":null,"clientSecret":null}""");
        JsonSerializer.Serialize(new PairOpened("r1", "sn", new DateTimeOffset(2026, 11, 6, 12, 30, 45, TimeSpan.Zero).AddTicks(1234567), "pt"), Web)
            .Should().Be("""{"requestId":"r1","serverNonce":"sn","expiresAt":"2026-11-06T12:30:45.1234567+00:00","pollToken":"pt"}""");
    }
}
