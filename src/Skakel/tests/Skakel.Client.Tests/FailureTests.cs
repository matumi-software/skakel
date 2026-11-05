using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text.Json;

namespace Skakel.Client.Tests;

/// <summary>Every failure is one of a fixed set, with fixed wording.</summary>
public sealed class FailureTests
{
    [Fact]
    public void VersionMismatch_names_both_sides_and_says_which_to_update()
    {
        SkakelFailure.VersionMismatch([2]).Message.Should().Be("This server speaks Skakel 2 and this app speaks Skakel 1. Update the app.");
        SkakelFailure.VersionMismatch([2, 3]).Message.Should().Be("This server speaks Skakel 2 and 3 and this app speaks Skakel 1. Update the app.");
        SkakelFailure.VersionMismatch([0]).Message.Should().EndWith("Update the server.");
        SkakelFailure.VersionMismatch([2]).Kind.Should().Be(SkakelFailureKind.VersionMismatch);
    }

    [Fact]
    public void Pick_takes_the_highest_common_version_or_none()
    {
        SkakelVersions.Pick([1, 2]).Should().Be(1);
        SkakelVersions.Pick([2, 3]).Should().BeNull();
        var refused = () => SkakelVersions.Require([4]);
        refused.Should().Throw<SkakelException>().Which.Failure.Kind.Should().Be(SkakelFailureKind.VersionMismatch);
    }

    [Fact]
    public void Of_has_wording_for_every_kind()
    {
        foreach (var kind in Enum.GetValues<SkakelFailureKind>())
        {
            var failure = SkakelFailure.Of(kind);
            failure.Message.Should().NotBeNullOrWhiteSpace();
            failure.Message.Should().NotContain("—").And.NotContain("–");
            failure.Code.Should().Be(char.ToLowerInvariant(kind.ToString()[0]) + kind.ToString()[1..]);
        }
    }

    [Fact]
    public void From_maps_exceptions_to_fixed_failures_never_their_text()
    {
        Kind(new HttpRequestException("ssl", new AuthenticationException("pin"))).Should().Be(SkakelFailureKind.CertificateMismatch);
        Kind(new TokenRequestException("invalid_client", HttpStatusCode.Unauthorized)).Should().Be(SkakelFailureKind.RejectedCredentials);
        Kind(new TokenRequestException("whatever", HttpStatusCode.TooManyRequests)).Should().Be(SkakelFailureKind.TooManyRequests);
        Kind(new HttpRequestException("401", null, HttpStatusCode.Unauthorized)).Should().Be(SkakelFailureKind.ClientUnknown);
        Kind(new HttpRequestException("404", null, HttpStatusCode.NotFound)).Should().Be(SkakelFailureKind.UnexpectedAnswer);
        Kind(new JsonException("bad")).Should().Be(SkakelFailureKind.UnexpectedAnswer);
        Kind(new HttpRequestException(HttpRequestError.ConfigurationLimitExceeded, "too long")).Should().Be(SkakelFailureKind.UnexpectedAnswer);
        Kind(new ArgumentOutOfRangeException("t", "past the calendar's end")).Should().Be(SkakelFailureKind.UnexpectedAnswer);
        Kind(new FormatException("not a header value")).Should().Be(SkakelFailureKind.UnexpectedAnswer);
        Kind(new HttpRequestException(HttpRequestError.ConnectionError, "refused", new SocketException((int)SocketError.ConnectionRefused))).Should().Be(SkakelFailureKind.Unreachable);
        Failures.Exception(new IOException("10.0.0.7:5240 reset")).Message.Should().NotContain("10.0.0.7");
    }

    [Fact]
    public void IsUnreachable_is_true_only_when_nothing_answered()
    {
        Failures.IsUnreachable(new HttpRequestException(HttpRequestError.ConnectionError, "refused", new SocketException((int)SocketError.ConnectionRefused))).Should().BeTrue();
        Failures.IsUnreachable(new HttpRequestException(HttpRequestError.NameResolutionError, "no such host")).Should().BeTrue();
        Failures.IsUnreachable(new TaskCanceledException("timeout", new TimeoutException())).Should().BeTrue();
        Failures.IsUnreachable(new HttpRequestException("ssl", new AuthenticationException("pin"))).Should().BeFalse("a server answered with another certificate");
        Failures.IsUnreachable(new TokenRequestException("invalid_client", HttpStatusCode.Unauthorized)).Should().BeFalse("a server refused the credentials");
    }

    [Fact]
    public void Credentials_never_print_the_secret()
    {
        new SkakelCredentials("client-1", "s3cret").ToString().Should().Contain("client-1").And.NotContain("s3cret");
    }

    private static SkakelFailureKind Kind(Exception ex) => Failures.From(ex).Kind;
}
