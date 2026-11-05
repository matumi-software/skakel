namespace Skakel.Protocol;

/// <summary>
/// The server's certificate and, while a handover is prepared, the next one. Sent as
/// <see cref="SkakelHubMethods.Certificates"/> when a hub connection opens and whenever either changes.
/// </summary>
/// <param name="Fingerprint">The certificate the server presents now.</param>
/// <param name="NextFingerprint">The one it will present after the switch, or null when none is prepared.</param>
public sealed record SkakelCertificates(string Fingerprint, string? NextFingerprint);

/// <summary>Sent as <see cref="SkakelHubMethods.Closing"/> just before the server ends a client's connections and streams.</summary>
/// <param name="Reason">One of <see cref="SkakelClosingReasons"/>.</param>
public sealed record SkakelClosing(string Reason);

/// <summary>Why the server ends a client's connections and streams.</summary>
public static class SkakelClosingReasons
{
    /// <summary>The client was revoked. Its credentials are gone.</summary>
    public const string Revoked = "revoked";

    /// <summary>The client's secret was rotated. Tokens from before no longer work.</summary>
    public const string Rotated = "rotated";

    /// <summary>The server is stopping, or no longer serves what the connection was for.</summary>
    public const string Stopping = "stopping";
}

/// <summary>The names of Skakel's own hub messages. Every other name belongs to the app, which may not start one with <see cref="Prefix"/>.</summary>
public static class SkakelHubMethods
{
    /// <summary>What every Skakel message name starts with.</summary>
    public const string Prefix = "Skakel";

    /// <summary>Server to client, with <see cref="Protocol.SkakelCertificates"/>.</summary>
    public const string Certificates = "SkakelCertificates";

    /// <summary>Server to client, with <see cref="Protocol.SkakelClosing"/>.</summary>
    public const string Closing = "SkakelClosing";

    /// <summary>Client to server, with the next certificate's fingerprint, once the client stored it.</summary>
    public const string NextCertificateReceived = "SkakelNextCertificateReceived";
}
