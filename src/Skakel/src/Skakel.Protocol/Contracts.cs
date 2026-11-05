namespace Skakel.Protocol;

/// <summary>The app a server belongs to.</summary>
/// <param name="Id">1 to 32 of <c>a-z</c>, <c>0-9</c> and <c>-</c>, such as <c>koppel</c>.</param>
/// <param name="Version">The app's own version, at most 32 characters.</param>
public sealed record SkakelApp(string Id, string Version);

/// <summary>What <c>GET /skakel/info</c> answers.</summary>
/// <param name="Name">The server's name, as discovery gives it.</param>
/// <param name="App">The app the server belongs to.</param>
/// <param name="Versions">The protocol versions the server speaks.</param>
public sealed record SkakelInfo(string Name, SkakelApp App, IReadOnlyList<int> Versions);

/// <summary>What <c>GET /skakel/v1/hello</c> answers to a token that works.</summary>
/// <param name="Server">The server's name.</param>
/// <param name="ClientId">The client the token was issued to.</param>
public sealed record SkakelHello(string Server, string ClientId);

/// <summary>
/// The body of a refusal, sent as <c>application/problem+json</c> (RFC 9457). <see cref="Detail"/> is
/// written for a person to read.
/// </summary>
/// <param name="Type">A URI for the kind of problem, often <c>about:blank</c> or a link to the HTTP status.</param>
/// <param name="Title">A short summary of the kind of problem.</param>
/// <param name="Status">The HTTP status code.</param>
/// <param name="Detail">What went wrong this time, for a person.</param>
public sealed record SkakelProblem(string? Type, string? Title, int? Status, string? Detail);
