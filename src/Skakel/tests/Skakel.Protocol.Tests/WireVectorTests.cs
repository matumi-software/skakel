using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Skakel.Protocol.Tests;

/// <summary>
/// Pins the bytes the Rust crate <c>skakel-protocol</c> pins too, with the same vectors, so the two
/// languages cannot drift apart without one of the suites failing.
/// </summary>
public sealed class WireVectorTests
{
    private const string Certificate = "MIIBHzCBxqADAgECAgh4tnYgc2q+xzAKBggqhkjOPQQDAjAWMRQwEgYDVQQDEwtza2FrZWwtdGVzdDAeFw0yNjAxMDEwMDAwMDBaFw0zNjAxMDEwMDAwMDBaMBYxFDASBgNVBAMTC3NrYWtlbC10ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9Qp6QPUFM5MDGOSKS+mZV+AmOGS49E487on6Ry4gB9Lt7LUai6B5Qk9QPOPWkvtq6zVkHClbtNRx33Iv7r3tGjAKBggqhkjOPQQDAgNIADBFAiAfWudN9OBxLvO/v3O5wKuXDbds95mmUjp56KAfnY7wBgIhALoHuJGsHQ4Pus6MSaBZwRKhh6VsTecKPoCMXlJ17VLy";

    [Fact]
    public void Of_gives_the_fingerprint_the_rust_side_pins()
    {
        using var certificate = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(Certificate));

        Fingerprints.Of(certificate).Should().Be("78:8D:08:D5:45:DB:3E:4C:51:D3:8A:4D:E2:7F:63:F0:72:1E:0B:D8:57:62:6A:E4:DB:22:B9:76:17:C5:6B:83");
    }

    [Fact]
    public void The_json_bodies_are_the_ones_the_rust_side_pins()
    {
        JsonSerializer.Serialize(new SkakelInfo("pi-lab", new SkakelApp("koppel", "0.1.1"), [1]), SkakelJson.Options)
            .Should().Be("""{"name":"pi-lab","app":{"id":"koppel","version":"0.1.1"},"versions":[1]}""");
        JsonSerializer.Serialize(new SkakelHello("pi-lab", "c1"), SkakelJson.Options)
            .Should().Be("""{"server":"pi-lab","clientId":"c1"}""");
        JsonSerializer.Serialize(new SkakelProblem("about:blank", null, null, null), SkakelJson.Options)
            .Should().Be("""{"type":"about:blank","title":null,"status":null,"detail":null}""");
        JsonSerializer.Serialize(new SkakelCertificates("AB", null), SkakelJson.Options)
            .Should().Be("""{"fingerprint":"AB","nextFingerprint":null}""");
        JsonSerializer.Serialize(new SkakelClosing("revoked"), SkakelJson.Options)
            .Should().Be("""{"reason":"revoked"}""");
    }

    [Fact]
    public void The_paths_and_lifetimes_are_the_ones_the_rust_side_pins()
    {
        SkakelProtocol.PairPath.Should().Be("/skakel/v1/pair");
        SkakelProtocol.TokenPath.Should().Be("/skakel/v1/token");
        SkakelProtocol.HelloPath.Should().Be("/skakel/v1/hello");
        SkakelProtocol.StreamsPath.Should().Be("/skakel/v1/streams");
        SkakelProtocol.AccessTokenLifetime.Should().Be(TimeSpan.FromSeconds(1800));
        SkakelCloseCodes.For(SkakelClosingReasons.Revoked).Should().Be(4001);
        SkakelCloseCodes.For(SkakelClosingReasons.Rotated).Should().Be(4002);
        SkakelCloseCodes.For(SkakelClosingReasons.Stopping).Should().Be(4003);
    }
}
