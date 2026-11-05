using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Skakel.Protocol.Tests;

public sealed class PairingCodeTests
{
    private const string Fingerprint = "EF:8E:16:AF:C3:88:BF:8C:94:CB:98:9A:3F:6A:93:F9:3D:0B:30:60:33:87:79:CF:C0:A4:E6:A4:30:89:14:29";

    [Fact]
    public void Compute_gives_the_same_six_digits_however_the_fingerprint_is_written()
    {
        var code = PairingCode.Compute(Fingerprint, "client-nonce", "server-nonce");

        code.Should().MatchRegex("^[0-9]{6}$");
        PairingCode.Compute(Fingerprint.Replace(":", "", StringComparison.Ordinal).ToLowerInvariant(), "client-nonce", "server-nonce").Should().Be(code);
    }

    [Fact]
    public void Compute_follows_the_derivation_in_the_protocol()
    {
        var hex = Fingerprint.Replace(":", "", StringComparison.Ordinal);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes($"skakel-pair-v1|{hex}|c|s"));
        var expected = (BinaryPrimitives.ReadUInt32BigEndian(hash) % 1_000_000).ToString("D6", CultureInfo.InvariantCulture);

        PairingCode.Compute(Fingerprint, "c", "s").Should().Be(expected);
    }

    [Fact]
    public void Compute_gives_another_code_for_another_certificate_or_nonce()
    {
        var code = PairingCode.Compute(Fingerprint, "a", "b");

        PairingCode.Compute(Fingerprint.Replace("EF", "EE", StringComparison.Ordinal), "a", "b").Should().NotBe(code);
        PairingCode.Compute(Fingerprint, "a2", "b").Should().NotBe(code);
        PairingCode.Compute(Fingerprint, "a", "b2").Should().NotBe(code);
    }

    [Fact]
    public void Matches_takes_only_the_nonce_the_commitment_was_made_from()
    {
        var nonce = PairingCode.NewNonce();
        var commitment = PairingCode.Commit(nonce);

        commitment.Should().MatchRegex("^[0-9A-F]{64}$");
        PairingCode.Matches(commitment, nonce).Should().BeTrue();
        PairingCode.Matches(commitment.ToLowerInvariant(), nonce).Should().BeTrue();
        PairingCode.Matches(commitment, PairingCode.NewNonce()).Should().BeFalse();
    }

    [Fact]
    public void NewNonce_is_32_bytes_of_base64url()
    {
        var nonce = PairingCode.NewNonce();

        nonce.Should().MatchRegex("^[A-Za-z0-9_-]{43}$");
        PairingCode.NewNonce().Should().NotBe(nonce);
    }

    [Fact]
    public void IsCode_ignores_spaces_but_wants_all_six_digits()
    {
        PairingCode.IsCode("482913", "482 913").Should().BeTrue();
        PairingCode.IsCode("482913", "482914").Should().BeFalse();
        PairingCode.IsCode("482913", "48291").Should().BeFalse();
        PairingCode.IsCode("482913", null).Should().BeFalse();
    }
}
