using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace Skakel.Protocol;

/// <summary>What a server tells clients that look for it.</summary>
/// <param name="Name">The name people know the server by.</param>
/// <param name="Port">Where its HTTPS listens.</param>
/// <param name="Fingerprint">The SHA-256 fingerprint of its certificate, which a client pins when it pairs.</param>
/// <param name="App">The app the server belongs to.</param>
/// <param name="Versions">The protocol versions it speaks.</param>
public sealed record DiscoveryAnswer(string Name, int Port, string Fingerprint, SkakelApp App, IReadOnlyList<int> Versions);

/// <summary>
/// The discovery packets. A client broadcasts a probe over UDP to its app's port; a server answers the
/// client directly with a <see cref="DiscoveryAnswer"/>. A probe is padded to <see cref="ProbeSize"/>
/// and an answer is never larger than the probe, so nobody can use a server to multiply traffic aimed
/// at someone else.
/// </summary>
public static class SkakelDiscovery
{
    /// <summary>
    /// For the discovery answer, which has to fit in a probe's size: text outside ASCII goes as UTF-8
    /// rather than as six-byte escapes. Never used for anything a browser renders.
    /// </summary>
    private static readonly JsonSerializerOptions Compact = new(JsonSerializerDefaults.Web)
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    /// <summary>A probe's size, and the most an answer may take.</summary>
    public const int ProbeSize = 512;

    /// <summary>The most characters of a server name a client keeps.</summary>
    public const int MaxNameLength = 63;

    /// <summary>The most characters an app id has.</summary>
    public const int MaxAppIdLength = SkakelProtocol.MaxAppIdLength;

    /// <summary>The most characters of an app version a client keeps.</summary>
    public const int MaxAppVersionLength = 32;

    /// <summary>The most protocol versions an answer lists.</summary>
    public const int MaxVersions = 8;

    /// <summary>The most servers a client keeps.</summary>
    public const int MaxEntries = 64;

    /// <summary>The most servers a client keeps from one address.</summary>
    public const int MaxEntriesPerAddress = 8;

    /// <summary>How often a client probes.</summary>
    public static readonly TimeSpan ProbeInterval = TimeSpan.FromSeconds(10);

    /// <summary>How long a client keeps a server that stopped answering: three missed probes.</summary>
    public static readonly TimeSpan EntryLifetime = TimeSpan.FromSeconds(35);

    /// <summary>A probe's first line. The <c>/1</c> is the packet layout's own version.</summary>
    public static ReadOnlySpan<byte> ProbeLine => "SKAKEL-DISCOVER/1\n"u8;

    /// <summary>An answer's first line. JSON with the server's details follows.</summary>
    public static ReadOnlySpan<byte> AnswerLine => "SKAKEL-SERVER/1\n"u8;

    /// <summary>A probe: the probe line, then zero padding to <see cref="ProbeSize"/>.</summary>
    public static byte[] CreateProbe()
    {
        var probe = new byte[ProbeSize];
        ProbeLine.CopyTo(probe);
        return probe;
    }

    /// <summary>True for a datagram a server answers: at least <see cref="ProbeSize"/> bytes, starting with the probe line.</summary>
    public static bool IsProbe(ReadOnlySpan<byte> datagram) => datagram.Length >= ProbeSize && datagram.StartsWith(ProbeLine);

    /// <summary>
    /// The answer to a probe. The name and the app version are cut to what a client keeps, and the name
    /// shortened further if that is what it takes to fit in <see cref="ProbeSize"/>.
    /// </summary>
    /// <exception cref="ArgumentException">The fingerprint, port, app id or versions are not ones a client would accept.</exception>
    public static byte[] CreateAnswer(DiscoveryAnswer answer)
    {
        ArgumentNullException.ThrowIfNull(answer);
        ArgumentNullException.ThrowIfNull(answer.App);
        var fingerprint = Fingerprints.Normalize(answer.Fingerprint) ?? throw new ArgumentException("The fingerprint must be 64 hex digits.", nameof(answer));
        if (answer.Port is < 1 or > 65535)
        {
            throw new ArgumentException("The port must be 1 to 65535.", nameof(answer));
        }

        if (!SkakelProtocol.IsAppId(answer.App.Id))
        {
            throw new ArgumentException("The app id must be 1 to 32 of a-z, 0-9 and -.", nameof(answer));
        }

        if (answer.Versions is not { Count: >= 1 and <= MaxVersions } versions || versions.Any(v => v < 1))
        {
            throw new ArgumentException($"List 1 to {MaxVersions} protocol versions.", nameof(answer));
        }

        var name = Clean(answer.Name, MaxNameLength);
        var app = new SkakelApp(answer.App.Id, Clean(answer.App.Version, MaxAppVersionLength));
        while (true)
        {
            var body = JsonSerializer.SerializeToUtf8Bytes(new DiscoveryAnswer(name, answer.Port, fingerprint, app, versions), Compact);
            if (AnswerLine.Length + body.Length <= ProbeSize)
            {
                return [.. AnswerLine, .. body];
            }

            // Only a name full of characters that take several bytes each gets here.
            if (name.Length == 0)
            {
                throw new ArgumentException("The answer does not fit in a probe.", nameof(answer));
            }

            name = name[..^(name.Length > 1 && char.IsLowSurrogate(name[^1]) ? 2 : 1)];
        }
    }

    /// <summary>
    /// Reads an answer, applying the limits a client applies. False for anything else: a wrong first
    /// line, broken JSON, a fingerprint that is not 64 hex digits, a name over 63 characters, an app id
    /// that is not one, an app version over 32 characters, or no versions or more than 8. Control
    /// and format characters in the name and version are dropped (see <see cref="Clean"/>). The fingerprint comes back in colon form.
    /// </summary>
    public static bool TryParseAnswer(ReadOnlySpan<byte> datagram, [NotNullWhen(true)] out DiscoveryAnswer? answer)
    {
        answer = null;
        if (!datagram.StartsWith(AnswerLine))
        {
            return false;
        }

        DiscoveryAnswer? body;
        try
        {
            body = JsonSerializer.Deserialize<DiscoveryAnswer>(datagram[AnswerLine.Length..], Compact);
        }
        catch (JsonException)
        {
            return false;
        }

        if (body is not { Name: { } name, Port: >= 1 and <= 65535, App: { Version: { } version } app, Versions: { Count: >= 1 and <= MaxVersions } versions }
            || Fingerprints.Normalize(body.Fingerprint) is not { } fingerprint
            || name.Length > MaxNameLength
            || version.Length > MaxAppVersionLength
            || !SkakelProtocol.IsAppId(app.Id)
            || versions.Any(v => v < 1))
        {
            return false;
        }

        answer = new DiscoveryAnswer(Clean(name, MaxNameLength), body.Port, fingerprint, new SkakelApp(app.Id, Clean(version, MaxAppVersionLength)), [.. versions]);
        return true;
    }

    /// <summary>
    /// Text a person can be shown: without control characters, format characters (such as bidi
    /// overrides and zero-width ones) or line and paragraph separators, trimmed and cut to
    /// <paramref name="maxLength"/> characters, never through a surrogate pair. What a client applies to
    /// a server's name and app version, from discovery and from info alike.
    /// </summary>
    /// <param name="text">The text, or null for none.</param>
    /// <param name="maxLength">The most characters kept.</param>
    public static string Clean(string? text, int maxLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(maxLength);
        var kept = new StringBuilder();
        foreach (var rune in (text ?? "").EnumerateRunes())
        {
            if (Rune.GetUnicodeCategory(rune) is not (UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator))
            {
                kept.Append(rune.ToString());
            }
        }

        var clean = kept.ToString().Trim();
        if (clean.Length <= maxLength)
        {
            return clean;
        }

        // Never half a surrogate pair.
        return clean[..(maxLength > 0 && char.IsHighSurrogate(clean[maxLength - 1]) ? maxLength - 1 : maxLength)];
    }
}
