using System.Reflection;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Skakel.Protocol;

namespace Skakel.Server;

/// <summary>Adds a Skakel server to an ASP.NET Core app.</summary>
public static class SkakelServerExtensions
{
    /// <summary>
    /// Adds the Skakel server: its state, the token server and validation, pairing, the live sessions,
    /// discovery and the rate limits. The app also registers an <see cref="ISkakelStore"/>, serves HTTPS
    /// with <see cref="SkakelHttpsExtensions.UseSkakelCertificate"/>, calls <c>UseWebSockets</c>, and maps
    /// the endpoints with <see cref="MapSkakel"/>.
    /// </summary>
    /// <remarks>
    /// This also puts a small middleware at the start of the app's pipeline, through a startup filter. It
    /// applies the per-address limits on <c>/skakel/v1/token</c> and <c>/skakel/v1/pair</c> and caps their
    /// bodies before routing, authentication or the app's own middleware run.
    /// </remarks>
    /// <param name="services">The app's services.</param>
    /// <param name="configure">Sets the app's id, version and port, and anything else in <see cref="SkakelServerOptions"/>.</param>
    public static IServiceCollection AddSkakelServer(this IServiceCollection services, Action<SkakelServerOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        services.AddOptions<SkakelServerOptions>()
            .Configure(configure)
            .ValidateOnStart();
        services.AddSingleton<IValidateOptions<SkakelServerOptions>, OptionsValidator>();

        services.TryAddSingleton(TimeProvider.System);

        // The state first: everything after it, Kestrel's certificate included, reads it.
        services.AddSingleton<ServerState>();
        services.AddHostedService(sp => sp.GetRequiredService<ServerState>());
        services.AddSingleton(sp => new SkakelClients(sp.GetRequiredService<ServerState>()));
        services.AddSingleton(sp => new SkakelKeys(sp.GetRequiredService<ServerState>()));
        services.AddSingleton(sp => new SkakelPairing(sp.GetRequiredService<ServerState>(), sp.GetRequiredService<TimeProvider>(), sp.GetRequiredService<ILogger<SkakelPairing>>()));
        services.AddSingleton(sp => new SkakelSessions(sp.GetRequiredService<ServerState>(), sp.GetRequiredService<IHostApplicationLifetime>(), sp.GetRequiredService<ILogger<SkakelSessions>>()));
        services.AddHostedService(sp => sp.GetRequiredService<SkakelSessions>());
        services.AddSingleton<SkakelDiscoveryService>();
        services.AddHostedService(sp => sp.GetRequiredService<SkakelDiscoveryService>());
        services.AddSingleton<SkakelRateLimits>();
        services.TryAddEnumerable(ServiceDescriptor.Transient<IStartupFilter, SkakelRequestGate.Startup>());

        services.AddSignalR();
        services.AddSkakelAuth();
        return services;
    }

    /// <summary>
    /// Maps <c>GET /skakel/info</c>, pairing at <c>/skakel/v1/pair</c>, tokens at <c>/skakel/v1/token</c>,
    /// <c>GET /skakel/v1/hello</c>, and the answer for a stream type nobody mapped. Returns a builder for
    /// all of them, with one for each, so the app can add its own conventions, such as which port serves them.
    /// </summary>
    /// <param name="endpoints">The app's endpoints.</param>
    public static SkakelEndpointConventionBuilder MapSkakel(this IEndpointRouteBuilder endpoints) => SkakelEndpoints.Map(endpoints);

    /// <summary>
    /// Maps the app's hub at <c>/skakel/v1/{path}</c>, behind a client's token, closing each connection
    /// when its token expires.
    /// </summary>
    /// <typeparam name="THub">The app's hub.</typeparam>
    /// <param name="endpoints">The app's endpoints.</param>
    /// <param name="path">The path under <c>/skakel/v1/</c>, such as <c>hub</c>.</param>
    /// <param name="configure">Further options for the hub's connections. <c>CloseOnAuthenticationExpiration</c> stays on whatever this sets.</param>
    /// <exception cref="ArgumentException">The path is taken by Skakel, or the hub or its client has a message name that starts with <c>Skakel</c>, in any case.</exception>
    public static HubEndpointConventionBuilder MapSkakelHub<THub>(this IEndpointRouteBuilder endpoints, string path, Action<Microsoft.AspNetCore.Http.Connections.HttpConnectionDispatcherOptions>? configure = null)
        where THub : Hub
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var relative = path.Trim('/');
        var first = relative.Split('/')[0];
        if (first is "pair" or "token" or "hello" or "streams")
        {
            throw new ArgumentException($"/skakel/v1/{first} is Skakel's own. Pick another path for the hub.", nameof(path));
        }

        CheckMessageNames(typeof(THub));
        return endpoints.MapHub<THub>($"{SkakelProtocol.BasePath}/{relative}", options =>
            {
                configure?.Invoke(options);

                // After the app's configure: a connection outliving its token would outlive a revoke or rotation's reach too.
                options.CloseOnAuthenticationExpiration = true;
            })
            .RequireSkakelClient();
    }

    /// <summary>
    /// Maps a stream type at <c>/skakel/v1/streams/{type}</c>. Skakel checks the token and the client's
    /// generation; <paramref name="handler"/> then checks the query string and the target, before the
    /// upgrade, and accepts with what runs inside the stream or refuses with 404, 409 or 422. The app
    /// calls <c>UseWebSockets</c>.
    /// </summary>
    /// <param name="endpoints">The app's endpoints.</param>
    /// <param name="type">The type: one or more of <c>a-z</c>, <c>0-9</c> and <c>-</c>.</param>
    /// <param name="handler">Decides whether the stream opens, and runs it.</param>
    public static IEndpointConventionBuilder MapSkakelStream(this IEndpointRouteBuilder endpoints, string type, SkakelStreamHandler handler)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(handler);
        if (!SkakelProtocol.IsStreamType(type))
        {
            throw new ArgumentException("A stream type is one or more of a-z, 0-9 and -.", nameof(type));
        }

        return SkakelEndpoints.MapStream(endpoints, type, handler);
    }

    /// <summary>
    /// App messages may not start with Skakel: the hub's own methods and the client interface's, by the
    /// name they go over the wire with, in any case, since SignalR matches hub methods without regard to case.
    /// </summary>
    private static void CheckMessageNames(Type hub)
    {
        var names = hub.GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .Where(m => !m.IsSpecialName && m.DeclaringType is { } declaring && !IsFramework(declaring))
            .Select(WireName);
        if (FindClientInterface(hub) is { } client)
        {
            names = names.Concat(new[] { client }.Concat(client.GetInterfaces()).SelectMany(i => i.GetMethods()).Select(WireName));
        }

        if (names.FirstOrDefault(n => n.StartsWith(SkakelHubMethods.Prefix, StringComparison.OrdinalIgnoreCase)) is { } taken)
        {
            throw new ArgumentException($"{hub.Name} has a message named {taken}. Names that start with {SkakelHubMethods.Prefix} are Skakel's own.", nameof(hub));
        }
    }

    private static string WireName(MethodInfo method) => method.GetCustomAttribute<HubMethodNameAttribute>()?.Name ?? method.Name;

    private static bool IsFramework(Type declaring) =>
        declaring == typeof(object) || declaring == typeof(Hub)
        || (declaring.IsGenericType && (declaring.GetGenericTypeDefinition() == typeof(Hub<>) || declaring.GetGenericTypeDefinition() == typeof(SkakelHub<>)));

    private static Type? FindClientInterface(Type hub)
    {
        for (var type = hub; type is not null; type = type.BaseType)
        {
            if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(Hub<>))
            {
                return type.GetGenericArguments()[0];
            }
        }

        return null;
    }

    /// <summary>Says which options are wrong, by name.</summary>
    private sealed class OptionsValidator : IValidateOptions<SkakelServerOptions>
    {
        public ValidateOptionsResult Validate(string? name, SkakelServerOptions options) =>
            options.Problems().ToList() is { Count: > 0 } problems ? ValidateOptionsResult.Fail(problems) : ValidateOptionsResult.Success;
    }
}
