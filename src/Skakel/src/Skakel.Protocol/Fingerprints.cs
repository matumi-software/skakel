using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Skakel.Protocol;

/// <summary>
/// Certificate fingerprints: the SHA-256 of the certificate, written as 32 hex pairs separated by
/// colons, such as <c>3F:9A:...</c>. Two fingerprints compare by their hex digits alone.
/// </summary>
public static class Fingerprints
{
    /// <summary>How many hex digits a fingerprint has.</summary>
    public const int HexDigits = 64;

    /// <summary>The fingerprint of <paramref name="certificate"/>, in colon form.</summary>
    public static string Of(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return string.Join(':', certificate.GetCertHash(HashAlgorithmName.SHA256).Select(b => b.ToString("X2", CultureInfo.InvariantCulture)));
    }

    /// <summary>
    /// The fingerprint in colon form, uppercase, or null unless the text is exactly 64 hex digits, with
    /// or without colons.
    /// </summary>
    public static string? Normalize(string? text)
    {
        if (text is null || text.Any(c => c != ':' && !Uri.IsHexDigit(c)))
        {
            return null;
        }

        var hex = text.Replace(":", "", StringComparison.Ordinal).ToUpperInvariant();
        return hex.Length == HexDigits ? string.Join(':', Enumerable.Range(0, 32).Select(i => hex.Substring(i * 2, 2))) : null;
    }

    /// <summary>True when both are the same fingerprint, by their hex digits alone, in constant time. Null and empty match nothing.</summary>
    public static bool AreEqual(string? a, string? b)
    {
        if (string.IsNullOrWhiteSpace(a) || string.IsNullOrWhiteSpace(b))
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Digits(a)), Encoding.ASCII.GetBytes(Digits(b)));
    }

    /// <summary>True when <paramref name="certificate"/> has the pinned fingerprint.</summary>
    public static bool Matches(X509Certificate2? certificate, string? pinned) =>
        certificate is not null && AreEqual(Of(certificate), pinned);

    /// <summary>True when <paramref name="certificate"/> has any of the pinned fingerprints. Null and empty ones match nothing.</summary>
    public static bool MatchesAny(X509Certificate2? certificate, params IEnumerable<string?> pinned)
    {
        ArgumentNullException.ThrowIfNull(pinned);
        return certificate is not null && pinned.Any(p => AreEqual(Of(certificate), p));
    }

    private static string Digits(string fingerprint) => new string([.. fingerprint.Where(Uri.IsHexDigit)]).ToUpperInvariant();
}
