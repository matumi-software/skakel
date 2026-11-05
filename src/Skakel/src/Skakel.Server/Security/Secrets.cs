using System.Security.Cryptography;
using System.Text;

namespace Skakel.Server.Security;

/// <summary>Creates, hashes and checks client secrets.</summary>
internal static class Secrets
{
    private const string Sha256Prefix = "sha256$";

    /// <summary>A new random secret, 32 bytes as base64url (43 characters).</summary>
    public static string NewSecret() => Base64Url(RandomNumberGenerator.GetBytes(32));

    /// <summary>A new random identifier with a readable prefix, such as <c>client-3f9a1c2b7d</c>.</summary>
    public static string NewId(string prefix) => $"{prefix}-{Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(5))}";

    /// <summary>A new random token: 32 bytes as hex.</summary>
    public static string NewToken() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

    /// <summary>
    /// SHA-256 hash, stored as <c>sha256$hash</c>. A client secret is 32 random bytes, so there is
    /// nothing to guess and a slow, salted hash would only make every token request expensive.
    /// </summary>
    public static string Hash(string secret)
    {
        ArgumentException.ThrowIfNullOrEmpty(secret);
        return Sha256Prefix + Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));
    }

    /// <summary>Checks a secret against a stored hash in constant time.</summary>
    public static bool Verify(string secret, string storedHash)
    {
        if (string.IsNullOrEmpty(secret) || string.IsNullOrEmpty(storedHash) || !storedHash.StartsWith(Sha256Prefix, StringComparison.Ordinal))
        {
            return false;
        }

        try
        {
            var expected = Convert.FromBase64String(storedHash[Sha256Prefix.Length..]);
            return CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(secret)), expected);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>Compares two tokens in constant time. A missing one matches nothing.</summary>
    public static bool SameToken(string expected, string? presented) =>
        !string.IsNullOrEmpty(presented)
        && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(presented));

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
