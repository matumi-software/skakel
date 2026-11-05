using System.Runtime.CompilerServices;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Skakel.Protocol;
using Skakel.Server;

namespace Skakel.Client.Tests;

/// <summary>Pairing against a real server: commitment, reveal, the code a person types, poll and withdraw.</summary>
public sealed class PairingTests : IAsyncLifetime
{
    private SkakelHost _host = null!;

    public async ValueTask InitializeAsync() => _host = await SkakelHost.StartAsync();

    public ValueTask DisposeAsync() => _host.DisposeAsync();

    [Fact]
    public async Task WaitAsync_hands_over_credentials_once_the_code_is_typed_on_the_server()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pairing = await SkakelPairingClient.OpenAsync(_host.Address, _host.Keys.Fingerprint, "laptop", cancellationToken: ct);

        pairing.ServerName.Should().Be("bench");
        pairing.Code.Should().MatchRegex("^[0-9]{6}$");
        var request = _host.Pairing.Overview.Requests.Should().ContainSingle().Subject;
        request.ClientName.Should().Be("laptop");
        (await _host.Pairing.ApproveAsync(request.Id, pairing.Code, ct)).Should().Be(SkakelApproval.Approved, "both ends derived the same code");

        var credentials = await pairing.WaitAsync(ct);

        _host.Clients.NameOf(credentials.ClientId).Should().Be("laptop");
        await using var link = new SkakelLink(_host.Address, pairing.Pins, credentials);
        (await link.HelloAsync(ct)).ClientId.Should().Be(credentials.ClientId);
    }

    [Fact]
    public async Task WaitAsync_reports_a_refusal()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pairing = await SkakelPairingClient.OpenAsync(_host.Address, _host.Keys.Fingerprint, "laptop", cancellationToken: ct);
        await _host.Pairing.DenyAsync(_host.Pairing.Overview.Requests.Single().Id);

        var wait = () => pairing.WaitAsync(ct);

        (await wait.Should().ThrowAsync<SkakelException>()).Which.Failure.Kind.Should().Be(SkakelFailureKind.PairingDenied);
    }

    [Fact]
    public async Task DisposeAsync_withdraws_a_waiting_request()
    {
        var ct = TestContext.Current.CancellationToken;
        var pairing = await SkakelPairingClient.OpenAsync(_host.Address, _host.Keys.Fingerprint, "laptop", cancellationToken: ct);
        _host.Pairing.Overview.Requests.Should().ContainSingle();

        await pairing.DisposeAsync();

        _host.Pairing.Overview.Requests.Should().BeEmpty();
    }

    [Fact]
    public async Task OpenAsync_refuses_a_server_with_another_certificate()
    {
        var other = string.Join(':', Enumerable.Repeat("0F", 32));

        var open = () => SkakelPairingClient.OpenAsync(_host.Address, other, "laptop", cancellationToken: TestContext.Current.CancellationToken);

        (await open.Should().ThrowAsync<SkakelException>()).Which.Failure.Kind.Should().Be(SkakelFailureKind.CertificateMismatch);
        _host.Pairing.Overview.Requests.Should().BeEmpty("nothing was sent before the certificate was checked");
    }

    [Fact]
    public async Task WaitAsync_gives_up_five_minutes_on_by_its_own_clock_whatever_the_server_says()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fake = await FakePairingAsync(DateTimeOffset.MaxValue, "f00d");
        var time = new ManualTimeProvider();
        await using var pairing = await SkakelPairingClient.OpenAsync(fake.Address, fake.Fingerprint, "laptop", new SkakelClientOptions { TimeProvider = time }, ct);
        pairing.ExpiresAt.Should().Be(time.GetUtcNow() + TimeSpan.FromMinutes(5));

        var wait = pairing.WaitAsync(ct);
        await time.WhenTimersAsync(1);
        time.Advance(TimeSpan.FromMinutes(6));

        var waiting = () => wait;
        (await waiting.Should().ThrowAsync<SkakelException>()).Which.Failure.Kind.Should().Be(SkakelFailureKind.PairingExpired);
    }

    [Theory]
    [InlineData("a\r\nb")]
    [InlineData("")]
    [InlineData("tab\there")]
    public async Task OpenAsync_refuses_a_poll_token_that_is_not_short_printable_text(string pollToken)
    {
        await using var fake = await FakePairingAsync(DateTimeOffset.UtcNow.AddMinutes(5), pollToken);

        var open = () => SkakelPairingClient.OpenAsync(fake.Address, fake.Fingerprint, "laptop", cancellationToken: TestContext.Current.CancellationToken);

        (await open.Should().ThrowAsync<SkakelException>()).Which.Failure.Kind.Should().Be(SkakelFailureKind.UnexpectedAnswer);
    }

    [Fact]
    public async Task OpenAsync_refuses_a_poll_token_over_128_characters()
    {
        await using var fake = await FakePairingAsync(DateTimeOffset.UtcNow.AddMinutes(5), new string('a', 129));

        var open = () => SkakelPairingClient.OpenAsync(fake.Address, fake.Fingerprint, "laptop", cancellationToken: TestContext.Current.CancellationToken);

        (await open.Should().ThrowAsync<SkakelException>()).Which.Failure.Kind.Should().Be(SkakelFailureKind.UnexpectedAnswer);
    }

    [Fact]
    public async Task OpenAsync_refuses_a_server_of_another_protocol_version()
    {
        _host.InfoVersions = [2];

        var open = () => SkakelPairingClient.OpenAsync(_host.Address, _host.Keys.Fingerprint, "laptop", cancellationToken: TestContext.Current.CancellationToken);

        var failure = (await open.Should().ThrowAsync<SkakelException>()).Which.Failure;
        failure.Kind.Should().Be(SkakelFailureKind.VersionMismatch);
        failure.Message.Should().Be("This server speaks Skakel 2 and this app speaks Skakel 1. Update the app.");
    }

    /// <summary>A server that opens every pairing request with this expiry and poll token, and keeps it waiting.</summary>
    private static Task<FakeServer> FakePairingAsync(DateTimeOffset expiresAt, string pollToken) => FakeServer.StartAsync(app =>
    {
        app.MapGet(SkakelProtocol.InfoPath, () => FakeServer.Info());
        app.MapPost(SkakelProtocol.PairPath, () => Results.Json(new { requestId = "r1", serverNonce = "n", expiresAt, pollToken }));
        app.MapPost($"{SkakelProtocol.PairPath}/r1/reveal", () => Results.NoContent());
        app.MapGet($"{SkakelProtocol.PairPath}/r1", () => Results.Json(new { state = "waiting" }));
        app.MapDelete($"{SkakelProtocol.PairPath}/r1", () => Results.NoContent());
    });
}

/// <summary>Polls quickly, so the tests do not wait two seconds a poll.</summary>
internal static class FastPolling
{
    [ModuleInitializer]
    internal static void Initialize() => SkakelPairingClient.PollInterval = TimeSpan.FromMilliseconds(100);
}
