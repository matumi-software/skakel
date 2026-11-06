namespace Skakel.Protocol;

/// <summary>Opens a pairing request: <c>POST /skakel/v1/pair</c>.</summary>
/// <param name="ClientName">1 to 80 characters after trimming.</param>
/// <param name="Commitment">The uppercase hex SHA-256 of the client's nonce (<see cref="PairingCode.Commit"/>).</param>
public sealed record PairOpenRequest(string? ClientName, string? Commitment);

/// <summary>What the server answers to an open. Only the opener ever sees the poll token.</summary>
/// <param name="RequestId">The request's handle, in the paths that follow.</param>
/// <param name="ServerNonce">The server's nonce for the code.</param>
/// <param name="ExpiresAt">When the request runs out.</param>
/// <param name="PollToken">Sent in the <c>X-Pair-Token</c> header to poll and to withdraw.</param>
public sealed record PairOpened(string RequestId, string ServerNonce, DateTimeOffset ExpiresAt, string PollToken);

/// <summary>Reveals the client's nonce: <c>POST /skakel/v1/pair/{requestId}/reveal</c>.</summary>
/// <param name="ClientNonce">The nonce the commitment was made from.</param>
public sealed record PairRevealRequest(string? ClientNonce);

/// <summary>What a poll answers: <c>GET /skakel/v1/pair/{requestId}</c>.</summary>
/// <param name="State">One of <see cref="PairStates"/>.</param>
/// <param name="ClientId">Once approved: the client's ID on this server.</param>
/// <param name="ClientSecret">Once approved: the client's secret. Handed over once.</param>
public sealed record PairPoll(string State, string? ClientId = null, string? ClientSecret = null);

/// <summary>The states a pairing request can be in.</summary>
public static class PairStates
{
    /// <summary>Waiting for a person to type the code on the server.</summary>
    public const string Waiting = "waiting";

    /// <summary>The code matched. The poll that sees this carries the credentials, once.</summary>
    public const string Approved = "approved";

    /// <summary>A person refused it, or the code was typed wrong three times.</summary>
    public const string Denied = "denied";

    /// <summary>The request ran out of time.</summary>
    public const string Expired = "expired";
}
