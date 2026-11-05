using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Validation;
using OpenIddict.Validation.AspNetCore;
using Skakel.Protocol;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Skakel.Server;

/// <summary>The names an app needs to put its own endpoints behind a Skakel client's token.</summary>
public static class SkakelServerDefaults
{
    /// <summary>
    /// The authorization policy for endpoints only registered clients may call: a bearer token over
    /// HTTPS, from a client still registered at the generation the token carries.
    /// </summary>
    public const string ClientPolicy = "skakel-client";

    /// <summary>The bearer authentication scheme the policy uses.</summary>
    public const string AuthenticationScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
}

/// <summary>What a validated Skakel token says.</summary>
public static class SkakelClaimsPrincipalExtensions
{
    /// <summary>The client ID a validated token was issued to.</summary>
    /// <param name="principal">The token's principal.</param>
    public static string? GetSkakelClientId(this ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        return principal.FindFirst(Claims.Subject)?.Value;
    }

    /// <summary>The client generation a validated token was issued for; null when it carries none.</summary>
    /// <param name="principal">The token's principal.</param>
    public static int? GetSkakelGeneration(this ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        return int.TryParse(principal.FindFirst(SkakelProtocol.GenerationClaim)?.Value, NumberStyles.None, CultureInfo.InvariantCulture, out var generation) ? generation : null;
    }
}

/// <summary>Puts endpoints behind a Skakel client's token.</summary>
public static class SkakelAuthorizationExtensions
{
    /// <summary>
    /// Lets only registered clients in: a bearer token over HTTPS, from a client still registered at the
    /// generation the token carries. A revoked client, or a token from before a rotation, is refused at once.
    /// </summary>
    /// <param name="builder">The endpoints.</param>
    public static TBuilder RequireSkakelClient<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder =>
        builder.RequireAuthorization(SkakelServerDefaults.ClientPolicy);
}

/// <summary>
/// The OAuth 2.0 client credentials server (OpenIddict in degraded mode, so clients live in the app's
/// store rather than a database) and bearer token validation.
/// </summary>
internal static class SkakelAuth
{
    public static void AddSkakelAuth(this IServiceCollection services)
    {
        services.AddOpenIddict()
            .AddServer(options =>
            {
                options.EnableDegradedMode();
                options.SetTokenEndpointUris(SkakelProtocol.TokenPath);
                options.AllowClientCredentialsFlow();
                options.SetAccessTokenLifetime(SkakelProtocol.AccessTokenLifetime);

                // Only access tokens are issued, and they are signed, not encrypted. The encryption key
                // OpenIddict insists on is never used, so a random one per start is enough. It is
                // symmetric: AddEphemeralEncryptionKey makes a 2048-bit RSA key on the first request,
                // which took 8 to 14 seconds on a low-power thin client and timed out its first caller.
                options.DisableAccessTokenEncryption();
                options.AddEncryptionKey(new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32)));

                // The token endpoint is an ordinary endpoint (see SkakelEndpoints), so it takes the app's
                // conventions and the rate limit, and checks the secret itself, after the rate limit.
                // OpenIddict only checks the request's shape first.
                options.UseAspNetCore().EnableTokenEndpointPassthrough();
                options.AddEventHandler<OpenIddictServerEvents.ValidateTokenRequestContext>(builder =>
                    builder.UseSingletonHandler<RequireClientCredentials>());
            })
            .AddValidation(options =>
            {
                options.UseLocalServer();
                options.UseAspNetCore();

                // A token from a revoked client, or from before a rotation, fails authentication itself, so it
                // is a 401 everywhere: Skakel's endpoints, the hub, the streams and the app's own.
                options.AddEventHandler<OpenIddictValidationEvents.ValidateTokenContext>(builder => builder
                    .UseSingletonHandler<RejectStaleGeneration>()
                    .SetOrder(OpenIddictValidationHandlers.Protection.ValidateExpirationDate.Descriptor.Order + 500));
            });

        // Only the current key signs. Validation also takes the keys it replaced, which are still live: the
        // local server integration copies the server's signing keys into the validation's configuration
        // first, and this adds the rest after it. Both option sets are built again when the keys change.
        services.AddOptions<OpenIddictServerOptions>()
            .Configure<ServerState>((options, state) =>
                options.SigningCredentials.Add(new SigningCredentials(state.SigningKey, SecurityAlgorithms.RsaSha256)));
        services.AddOptions<OpenIddictValidationOptions>()
            .Configure<ServerState>((options, state) =>
            {
                if (options.Configuration is not { } configuration)
                {
                    return;
                }

                foreach (var key in state.ValidationKeys.Where(key => configuration.SigningKeys.All(known => known.KeyId != key.KeyId)))
                {
                    configuration.SigningKeys.Add(key);
                }
            });
        services.AddSingleton<IOptionsChangeTokenSource<OpenIddictServerOptions>, SigningKeyChange<OpenIddictServerOptions>>();
        services.AddSingleton<IOptionsChangeTokenSource<OpenIddictValidationOptions>, SigningKeyChange<OpenIddictValidationOptions>>();

        services.AddAuthentication();
        services.AddAuthorizationBuilder()
            .AddPolicy(SkakelServerDefaults.ClientPolicy, policy => policy
                .AddAuthenticationSchemes(SkakelServerDefaults.AuthenticationScheme)
                .RequireAuthenticatedUser()
                .AddRequirements(new CurrentClientRequirement()));
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAuthorizationHandler, CurrentClientHandler>());
    }

    /// <summary>A failed token request: the OAuth error, never the reason the secret was wrong.</summary>
    public static IResult Refuse(string error, string description) =>
        TypedResults.Forbid(
            new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description,
            }),
            [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);

    /// <summary>Issues a token to a client whose secret was checked at <paramref name="generation"/>.</summary>
    public static IResult Issue(string clientId, int generation)
    {
        var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);
        identity.SetClaim(Claims.Subject, clientId);
        identity.SetClaim(SkakelProtocol.GenerationClaim, generation.ToString(CultureInfo.InvariantCulture));
        identity.SetDestinations(static _ => [Destinations.AccessToken]);
        return TypedResults.SignIn(new ClaimsPrincipal(identity), authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    /// <summary>A bearer token sent over plain HTTP has already leaked; refuse it.</summary>
    public static bool IsHttps(object? resource) => resource switch
    {
        HttpContext http => http.Request.IsHttps,
        HubInvocationContext hub => hub.Context.GetHttpContext()?.Request.IsHttps == true,
        _ => false,
    };

    /// <summary>Tells the options system to build the token server's and the validation's options again when the keys change.</summary>
    private sealed class SigningKeyChange<TOptions>(ServerState state) : IOptionsChangeTokenSource<TOptions>
    {
        public string Name => Options.DefaultName;

        public IChangeToken GetChangeToken() => state.GetChangeToken();
    }

    /// <summary>
    /// Degraded mode wants a handler that validates token requests. This one takes only client
    /// credentials with both the ID and the secret; the endpoint checks the secret.
    /// </summary>
    private sealed class RequireClientCredentials : IOpenIddictServerHandler<OpenIddictServerEvents.ValidateTokenRequestContext>
    {
        public ValueTask HandleAsync(OpenIddictServerEvents.ValidateTokenRequestContext context)
        {
            if (!context.Request.IsClientCredentialsGrantType())
            {
                context.Reject(Errors.UnsupportedGrantType, "Only the client_credentials grant is supported.");
            }
            else if (string.IsNullOrEmpty(context.ClientId) || string.IsNullOrEmpty(context.ClientSecret))
            {
                context.Reject(Errors.InvalidClient, "The client ID or secret is wrong, or the client was revoked.");
            }

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>Refuses a token whose client is gone, or is at another generation now.</summary>
    private sealed class RejectStaleGeneration(ServerState state) : IOpenIddictValidationHandler<OpenIddictValidationEvents.ValidateTokenContext>
    {
        public ValueTask HandleAsync(OpenIddictValidationEvents.ValidateTokenContext context)
        {
            if (context.Principal is { } principal && !state.IsCurrent(principal))
            {
                context.Reject(Errors.InvalidToken, "The client was revoked, or its secret was rotated since this token was issued.");
            }

            return ValueTask.CompletedTask;
        }
    }

    private sealed class CurrentClientRequirement : IAuthorizationRequirement;

    /// <summary>The token is over HTTPS, and its client is still registered at the token's generation.</summary>
    private sealed class CurrentClientHandler(ServerState state) : AuthorizationHandler<CurrentClientRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, CurrentClientRequirement requirement)
        {
            if (IsHttps(context.Resource) && state.IsCurrent(context.User))
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }
}
