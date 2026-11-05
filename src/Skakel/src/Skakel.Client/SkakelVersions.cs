using Skakel.Protocol;

namespace Skakel.Client;

/// <summary>Picking the protocol version to speak with a server.</summary>
public static class SkakelVersions
{
    /// <summary>The highest version both this client and the server speak, or null when there is none.</summary>
    /// <param name="serverVersions">The versions the server listed, from discovery or <c>/skakel/info</c>.</param>
    public static int? Pick(IEnumerable<int> serverVersions)
    {
        ArgumentNullException.ThrowIfNull(serverVersions);
        var common = serverVersions.Intersect(SkakelProtocol.Versions).ToList();
        return common.Count == 0 ? null : common.Max();
    }

    /// <summary>The version to speak. Throws a <see cref="SkakelFailureKind.VersionMismatch"/> that names both sides' versions when there is none.</summary>
    /// <param name="serverVersions">The versions the server listed.</param>
    /// <exception cref="SkakelException">The server speaks none of this client's versions.</exception>
    public static int Require(IReadOnlyCollection<int> serverVersions) =>
        Pick(serverVersions) ?? throw new SkakelException(SkakelFailure.VersionMismatch(serverVersions));
}
