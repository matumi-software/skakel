namespace Skakel.Protocol;

/// <summary>The numbers, paths and names of Skakel protocol version 1. See <c>docs/protocol.md</c>.</summary>
public static class SkakelProtocol
{
    /// <summary>The protocol version this library speaks.</summary>
    public const int Version = 1;

    /// <summary>The protocol versions this library speaks, as a server lists them.</summary>
    public static IReadOnlyList<int> Versions { get; } = [Version];

    /// <summary>The unversioned info endpoint: <c>GET</c>, no token.</summary>
    public const string InfoPath = "/skakel/info";

    /// <summary>Every versioned path starts with this.</summary>
    public const string BasePath = "/skakel/v1";

    /// <summary>Opens a pairing request: <c>POST</c>. Reveal, poll and withdraw are under <c>{PairPath}/{requestId}</c>.</summary>
    public const string PairPath = BasePath + "/pair";

    /// <summary>OAuth 2.0 client credentials: <c>POST</c>.</summary>
    public const string TokenPath = BasePath + "/token";

    /// <summary>Checks credentials: <c>GET</c> with a token.</summary>
    public const string HelloPath = BasePath + "/hello";

    /// <summary>Streams open at <c>{StreamsPath}/{type}</c>.</summary>
    public const string StreamsPath = BasePath + "/streams";

    /// <summary>The header that carries a pairing request's poll token.</summary>
    public const string PairTokenHeader = "X-Pair-Token";

    /// <summary>The access token claim that carries the client's generation.</summary>
    public const string GenerationClaim = "skakel_generation";

    /// <summary>How long an access token lasts.</summary>
    public static readonly TimeSpan AccessTokenLifetime = TimeSpan.FromMinutes(30);

    /// <summary>How often both ends of a stream ping.</summary>
    public static readonly TimeSpan StreamKeepAliveInterval = TimeSpan.FromSeconds(15);

    /// <summary>How long an end of a stream waits for an answer to its ping before it gives up.</summary>
    public static readonly TimeSpan StreamKeepAliveTimeout = TimeSpan.FromSeconds(30);

    /// <summary>The media type of a refusal's body.</summary>
    public const string ProblemContentType = "application/problem+json";

    /// <summary>True for a stream type: one or more of <c>a-z</c>, <c>0-9</c> and <c>-</c>.</summary>
    public static bool IsStreamType(string? type) => !string.IsNullOrEmpty(type) && type.All(IsNameCharacter);

    /// <summary>True for an app id: 1 to 32 of <c>a-z</c>, <c>0-9</c> and <c>-</c>.</summary>
    public static bool IsAppId(string? id) => id is { Length: >= 1 and <= SkakelDiscovery.MaxAppIdLength } && id.All(IsNameCharacter);

    private static bool IsNameCharacter(char c) => c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-';
}
