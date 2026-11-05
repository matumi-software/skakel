using System.Net;
using Skakel.Protocol;

namespace Skakel.Client;

/// <summary>A server that answered a discovery probe.</summary>
/// <param name="Name">The name people know it by; its address when it gave none.</param>
/// <param name="Address">Where the answer came from, which is where to reach it.</param>
/// <param name="Port">Its HTTPS port.</param>
/// <param name="Fingerprint">Its certificate's fingerprint, in colon form. Anyone on the network can copy it; pairing and pinning are what prove it.</param>
/// <param name="App">The app it belongs to.</param>
/// <param name="Versions">The protocol versions it speaks.</param>
public sealed record SkakelDiscoveredServer(string Name, IPAddress Address, int Port, string Fingerprint, SkakelApp App, IReadOnlyList<int> Versions)
{
    /// <summary>Its HTTPS address, such as <c>https://192.168.1.20:5240/</c>.</summary>
    public Uri Url => new UriBuilder(Uri.UriSchemeHttps, Address.ToString(), Port).Uri;

    /// <summary>The highest protocol version it and this client both speak, or null when there is none.</summary>
    public int? Version => SkakelVersions.Pick(Versions);

    /// <summary>The same server as the same answer: the versions compare by value.</summary>
    /// <param name="other">The other entry.</param>
    public bool Equals(SkakelDiscoveredServer? other) =>
        other is not null
        && Name == other.Name
        && Address.Equals(other.Address)
        && Port == other.Port
        && Fingerprint == other.Fingerprint
        && App == other.App
        && Versions.SequenceEqual(other.Versions);

    /// <inheritdoc />
    public override int GetHashCode() => HashCode.Combine(Name, Address, Port, Fingerprint, App);
}
