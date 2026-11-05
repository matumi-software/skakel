using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.DependencyInjection;
using Skakel.Protocol;

namespace Skakel.Server;

/// <summary>
/// The base of an app's SignalR hub for its Skakel clients. Map it with <c>MapSkakelHub</c>, which
/// puts it behind a client's token. On connect it tells the client the server's certificates
/// (<c>SkakelCertificates</c>), and it takes <c>SkakelNextCertificateReceived</c> from the client. A
/// connection ends when its token expires, and when its client is revoked or rotated or the server
/// stops, after <c>SkakelClosing</c>.
/// </summary>
/// <remarks>
/// An app that overrides <see cref="OnConnectedAsync"/> or <see cref="OnDisconnectedAsync"/> calls the
/// base first. Its own message names may not start with <c>Skakel</c>.
/// </remarks>
/// <typeparam name="TClient">The app's messages to the client.</typeparam>
public abstract class SkakelHub<TClient> : Hub<TClient>
    where TClient : class
{
    private const string SessionKey = "skakel.session";

    /// <summary>The client this connection belongs to.</summary>
    protected string SkakelClientId => Context.User?.GetSkakelClientId() ?? throw new InvalidOperationException("The connection has no Skakel client.");

    /// <summary>Tracks the connection, so a revoke or rotation ends it, and tells the client the server's certificates.</summary>
    public override async Task OnConnectedAsync()
    {
        var services = Context.GetHttpContext()?.RequestServices ?? throw new InvalidOperationException("A Skakel hub runs over HTTP.");
        var user = Context.User;
        if (user?.GetSkakelClientId() is not { } clientId || user.GetSkakelGeneration() is not { } generation)
        {
            Context.Abort();
            return;
        }

        var hub = (IHubContext)services.GetRequiredService(typeof(IHubContext<>).MakeGenericType(GetType()));
        var caller = hub.Clients.Client(Context.ConnectionId);
        var session = services.GetRequiredService<SkakelSessions>().AddHub(clientId, generation, caller, Context.Abort);
        Context.Items[SessionKey] = session;
        try
        {
            await caller.SendAsync(SkakelHubMethods.Certificates, services.GetRequiredService<ServerState>().Certificates, Context.ConnectionAborted);
            await base.OnConnectedAsync();
        }
        catch
        {
            // SignalR does not call OnDisconnectedAsync for a connection whose OnConnectedAsync failed, such as one
            // that dropped during the first send, so the session would never be let go.
            Context.Items.Remove(SessionKey);
            session.Dispose();
            throw;
        }
    }

    /// <summary>Stops tracking the connection.</summary>
    /// <param name="exception">Why it ended, when it failed.</param>
    public override Task OnDisconnectedAsync(Exception? exception)
    {
        (Context.Items.Remove(SessionKey, out var session) ? session as IDisposable : null)?.Dispose();
        return base.OnDisconnectedAsync(exception);
    }

    /// <summary>
    /// The client stored the next certificate's fingerprint. The app's UI shows who has it
    /// (<see cref="SkakelClientView.HasNextCertificate"/>), so a person knows when to switch.
    /// </summary>
    /// <param name="fingerprint">The fingerprint the client stored.</param>
    public async Task SkakelNextCertificateReceived(string fingerprint)
    {
        var state = Context.GetHttpContext()?.RequestServices.GetRequiredService<ServerState>();
        if (state is not null && state.IsCurrent(Context.User) && !string.IsNullOrEmpty(fingerprint))
        {
            await state.MarkNextCertificateReceivedAsync(SkakelClientId, fingerprint, Context.ConnectionAborted);
        }
    }
}
