using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Skakel.Protocol.Tests;

public sealed class FingerprintsTests
{
    [Fact]
    public void Normalize_gives_the_colon_form_or_null()
    {
        var hex = new string('a', 64);

        Fingerprints.Normalize(hex).Should().Be(string.Join(':', Enumerable.Repeat("AA", 32)));
        Fingerprints.Normalize(string.Join(':', Enumerable.Repeat("aa", 32))).Should().Be(string.Join(':', Enumerable.Repeat("AA", 32)));
        Fingerprints.Normalize(new string('a', 62)).Should().BeNull();
        Fingerprints.Normalize(new string('a', 66)).Should().BeNull();
        Fingerprints.Normalize(new string('g', 64)).Should().BeNull();
        Fingerprints.Normalize(null).Should().BeNull();
    }

    [Fact]
    public void AreEqual_compares_by_hex_digits_alone()
    {
        var colon = string.Join(':', Enumerable.Repeat("AB", 32));

        Fingerprints.AreEqual(colon, new string('a', 1) + string.Concat(Enumerable.Repeat("ba", 31)) + "b").Should().BeTrue();
        Fingerprints.AreEqual(colon, colon.Replace("AB", "AC", StringComparison.Ordinal)).Should().BeFalse();
        Fingerprints.AreEqual(colon, null).Should().BeFalse();
        Fingerprints.AreEqual("", "").Should().BeFalse();
    }

    [Fact]
    public void Matches_takes_the_certificate_s_own_fingerprint_and_no_other()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var certificate = new CertificateRequest("CN=test", key, HashAlgorithmName.SHA256).CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));
        var fingerprint = Fingerprints.Of(certificate);

        fingerprint.Should().MatchRegex("^([0-9A-F]{2}:){31}[0-9A-F]{2}$");
        Fingerprints.Matches(certificate, fingerprint.ToLowerInvariant().Replace(":", "", StringComparison.Ordinal)).Should().BeTrue();
        Fingerprints.Matches(certificate, string.Join(':', Enumerable.Repeat("00", 32))).Should().BeFalse();
        Fingerprints.MatchesAny(certificate, null, "", fingerprint).Should().BeTrue();
        Fingerprints.MatchesAny(null, fingerprint).Should().BeFalse();
    }
}
