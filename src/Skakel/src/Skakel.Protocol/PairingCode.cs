using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Skakel.Protocol;

/// <summary>
/// The six-digit code a person types on the server to approve a client. The protocol behind it is
/// numeric comparison with a commitment, as in Bluetooth pairing:
/// <list type="number">
/// <item>The client sends <see cref="Commit"/> of a random nonce, not the nonce.</item>
/// <item>The server answers with its own random nonce.</item>
/// <item>The client reveals its nonce; the server checks it against the commitment.</item>
/// </list>
/// Both ends then derive the code from the certificate the client pinned and both nonces. A man in
/// the middle has its own certificate and must fix each nonce before it sees the other side's, so it
/// cannot steer the two codes to match: for each request it gets one guess in a million. That holds
/// per request, not overall, so the server also limits how many requests it takes. The code is never
/// sent.
/// </summary>
public static class PairingCode
{
    /// <summary>How many digits the code has.</summary>
    public const int Digits = 6;

    /// <summary>A fresh random nonce: 32 bytes as base64url.</summary>
    public static string NewNonce() => Base64Url(RandomNumberGenerator.GetBytes(32));

    /// <summary>The commitment a client sends before revealing its nonce: the uppercase hex SHA-256 of its UTF-8 bytes.</summary>
    public static string Commit(string nonce)
    {
        ArgumentNullException.ThrowIfNull(nonce);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(nonce)));
    }

    /// <summary>True when <paramref name="nonce"/> is the one <paramref name="commitment"/> was made from. Case is ignored.</summary>
    public static bool Matches(string commitment, string nonce)
    {
        ArgumentNullException.ThrowIfNull(commitment);
        ArgumentNullException.ThrowIfNull(nonce);
        return CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(commitment.ToUpperInvariant()), Encoding.ASCII.GetBytes(Commit(nonce)));
    }

    /// <summary>The code, such as <c>482913</c>. Fingerprints compare by their hex digits alone.</summary>
    public static string Compute(string fingerprint, string clientNonce, string serverNonce)
    {
        ArgumentNullException.ThrowIfNull(fingerprint);
        var hex = new string([.. fingerprint.Where(Uri.IsHexDigit)]).ToUpperInvariant();
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes($"skakel-pair-v1|{hex}|{clientNonce}|{serverNonce}"));
        var value = BinaryPrimitives.ReadUInt32BigEndian(hash) % 1_000_000;
        return value.ToString("D6", CultureInfo.InvariantCulture);
    }

    /// <summary>Compares a typed code with the expected one, ignoring anything but digits, in constant time.</summary>
    public static bool IsCode(string expected, string? typed)
    {
        ArgumentNullException.ThrowIfNull(expected);
        var digits = new string([.. (typed ?? "").Where(char.IsAsciiDigit)]);
        return digits.Length == Digits
            && CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(digits));
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
