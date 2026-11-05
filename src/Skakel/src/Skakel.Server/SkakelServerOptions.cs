using Skakel.Protocol;

namespace Skakel.Server;

/// <summary>How an app's Skakel server presents itself and what it allows. Set with <c>AddSkakelServer</c>.</summary>
public sealed class SkakelServerOptions
{
    /// <summary>The app's id: 1 to 32 of <c>a-z</c>, <c>0-9</c> and <c>-</c>, such as <c>koppel</c>. Required.</summary>
    public string AppId { get; set; } = "";

    /// <summary>The app's version, as clients show it. At most 32 characters. Required.</summary>
    public string AppVersion { get; set; } = "";

    /// <summary>The name people know this server by. The machine's name unless set.</summary>
    public string Name { get; set; } = Environment.MachineName;

    /// <summary>The TCP port clients reach the server's HTTPS on, which discovery announces. Required.</summary>
    public int Port { get; set; }

    /// <summary>Whether to answer discovery probes. On unless turned off.</summary>
    public bool DiscoveryEnabled { get; set; } = true;

    /// <summary>The UDP port discovery answers on. <see cref="Port"/> unless set. 0 picks a free one, for tests.</summary>
    public int? DiscoveryPort { get; set; }

    /// <summary>Token requests allowed per minute from one address. The protocol says 60.</summary>
    public int TokenRequestsPerMinute { get; set; } = 60;

    /// <summary>Pairing requests (open, reveal, poll and withdraw together) allowed per minute from one address. The protocol says 120.</summary>
    public int PairRequestsPerMinute { get; set; } = 120;

    /// <summary>
    /// Keep each client's secret in the state beside its hash, so the app can show it again. Off unless
    /// set: then only the hash is kept, and a lost secret is replaced by rotating it.
    /// </summary>
    public bool KeepClientSecrets { get; set; }

    /// <summary>The host name in a new certificate. The machine's name unless set. Clients pin the fingerprint, so it is only for people reading the certificate.</summary>
    public string CertificateHostName { get; set; } = Environment.MachineName;

    /// <summary>What discovery and the info endpoint say about the app.</summary>
    internal SkakelApp App => new(AppId, AppVersion);

    internal IEnumerable<string> Problems()
    {
        if (!SkakelProtocol.IsAppId(AppId))
        {
            yield return $"{nameof(AppId)} must be 1 to {SkakelDiscovery.MaxAppIdLength} of a-z, 0-9 and -.";
        }

        if (string.IsNullOrWhiteSpace(AppVersion) || AppVersion.Length > SkakelDiscovery.MaxAppVersionLength)
        {
            yield return $"{nameof(AppVersion)} must be 1 to {SkakelDiscovery.MaxAppVersionLength} characters.";
        }

        if (string.IsNullOrWhiteSpace(Name))
        {
            yield return $"{nameof(Name)} must not be empty.";
        }

        if (Port is < 1 or > 65535)
        {
            yield return $"{nameof(Port)} must be 1 to 65535.";
        }

        if (DiscoveryPort is < 0 or > 65535)
        {
            yield return $"{nameof(DiscoveryPort)} must be 0 to 65535.";
        }

        if (TokenRequestsPerMinute < 1 || PairRequestsPerMinute < 1)
        {
            yield return "The rate limits must allow at least one request a minute.";
        }

        if (string.IsNullOrWhiteSpace(CertificateHostName))
        {
            yield return $"{nameof(CertificateHostName)} must not be empty.";
        }
    }
}
