namespace Skakel.Client.Tests;

/// <summary>A link against a real server: connecting, the app's own hub messages, and every way it fails.</summary>
public sealed class LinkTests : IAsyncLifetime
{
    private SkakelHost _host = null!;

    public async ValueTask InitializeAsync() => _host = await SkakelHost.StartAsync();

    public ValueTask DisposeAsync() => _host.DisposeAsync();

    [Fact]
    public async Task Start_connects_the_hub()
    {
        var (link, credentials) = await _host.LinkAsync();
        await using var _ = link;
        var statuses = Record(link);

        link.Start();

        await statuses.WaitAsync(s => s.State == SkakelLinkState.Connected);
        statuses.Seen.Select(s => s.State).Should().Equal(SkakelLinkState.Connecting, SkakelLinkState.Connected);
        (await link.HelloAsync(TestContext.Current.CancellationToken)).Should().Be(new Skakel.Protocol.SkakelHello("bench", credentials.ClientId));
    }

    [Fact]
    public async Task On_and_InvokeAsync_carry_the_apps_own_messages()
    {
        var ct = TestContext.Current.CancellationToken;
        var (link, credentials) = await _host.LinkAsync();
        await using var _ = link;
        var greetings = new Recorder<string>();
        using var handler = link.On<string>(nameof(ITestClient.Greeted), greetings.Record);
        var statuses = Record(link);
        link.Start();
        await statuses.WaitAsync(s => s.State == SkakelLinkState.Connected);

        await link.InvokeAsync(nameof(TestHub.Greet), ["hello"], ct);

        (await greetings.WaitAsync(_ => true)).Should().Be($"{credentials.ClientId}: hello");
        (await link.InvokeAsync<string>(nameof(TestHub.Echo), ["echo"], ct)).Should().Be("echo");
    }

    [Fact]
    public async Task On_refuses_a_name_that_is_Skakels_own()
    {
        var (link, _) = await _host.LinkAsync();
        await using var __ = link;

        var on = () => link.On<string>("SkakelSomething", _ => Task.CompletedTask);
        var invoke = () => link.InvokeAsync("SkakelSomething", cancellationToken: TestContext.Current.CancellationToken);

        on.Should().Throw<ArgumentException>();
        await invoke.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task InvokeAsync_says_not_connected_before_the_link_is()
    {
        var (link, _) = await _host.LinkAsync();
        await using var __ = link;

        var invoke = () => link.InvokeAsync(nameof(TestHub.Echo), ["x"], TestContext.Current.CancellationToken);

        (await invoke.Should().ThrowAsync<SkakelException>()).Which.Failure.Kind.Should().Be(SkakelFailureKind.NotConnected);
    }

    [Fact]
    public async Task A_wrong_secret_is_rejected_credentials()
    {
        var credentials = await _host.RegisterAsync();
        await using var link = new SkakelLink(_host.Address, _host.Pins, credentials with { ClientSecret = "wrong" });
        var statuses = Record(link);

        link.Start();

        (await statuses.WaitAsync(s => s.State == SkakelLinkState.Failed)).Failure!.Kind.Should().Be(SkakelFailureKind.RejectedCredentials);
        await ShouldFail(() => link.HelloAsync(TestContext.Current.CancellationToken), SkakelFailureKind.RejectedCredentials);
    }

    [Fact]
    public async Task Another_certificate_is_a_mismatch()
    {
        var credentials = await _host.RegisterAsync();
        await using var link = new SkakelLink(_host.Address, new SkakelPins(string.Join(':', Enumerable.Repeat("0F", 32))), credentials);
        var statuses = Record(link);

        link.Start();

        (await statuses.WaitAsync(s => s.State == SkakelLinkState.Failed)).Failure!.Kind.Should().Be(SkakelFailureKind.CertificateMismatch);
    }

    [Fact]
    public async Task A_closed_port_is_unreachable()
    {
        var credentials = await _host.RegisterAsync();
        await using var link = new SkakelLink(new Uri($"https://127.0.0.1:{Ports.FreeTcp()}"), _host.Pins, credentials);

        var failure = await ShouldFail(() => link.HelloAsync(TestContext.Current.CancellationToken), SkakelFailureKind.Unreachable);

        failure.Message.Should().Be("Could not reach the server. Check the address and that the server is running.");
    }

    [Fact]
    public async Task A_server_of_another_version_is_a_version_mismatch()
    {
        _host.InfoVersions = [2];
        var (link, _) = await _host.LinkAsync();
        await using var __ = link;
        var statuses = Record(link);

        link.Start();

        var failure = (await statuses.WaitAsync(s => s.State == SkakelLinkState.Failed)).Failure!;
        failure.Kind.Should().Be(SkakelFailureKind.VersionMismatch);
        failure.Message.Should().Be("This server speaks Skakel 2 and this app speaks Skakel 1. Update the app.");
    }

    [Fact]
    public async Task Revoking_the_client_closes_the_link_for_good()
    {
        var (link, credentials) = await _host.LinkAsync();
        await using var _ = link;
        var statuses = Record(link);
        link.Start();
        await statuses.WaitAsync(s => s.State == SkakelLinkState.Connected);

        await _host.Clients.RevokeAsync(credentials.ClientId, TestContext.Current.CancellationToken);

        var closed = await statuses.WaitAsync(s => s.State == SkakelLinkState.Closed);
        closed.Failure!.Kind.Should().Be(SkakelFailureKind.Revoked);
        closed.Failure.Message.Should().Be("The server revoked this client. Pair with the server again.");
    }

    [Fact]
    public async Task Rotating_the_secret_closes_the_link_for_good()
    {
        var (link, credentials) = await _host.LinkAsync();
        await using var _ = link;
        var statuses = Record(link);
        link.Start();
        await statuses.WaitAsync(s => s.State == SkakelLinkState.Connected);

        await _host.Clients.RotateSecretAsync(credentials.ClientId, TestContext.Current.CancellationToken);

        (await statuses.WaitAsync(s => s.State == SkakelLinkState.Closed)).Failure!.Kind.Should().Be(SkakelFailureKind.Rotated);
    }

    [Fact]
    public async Task A_server_that_ends_every_connection_is_connected_to_again()
    {
        var (link, _) = await _host.LinkAsync();
        await using var __ = link;
        var statuses = Record(link);
        link.Start();
        await statuses.WaitAsync(s => s.State == SkakelLinkState.Connected);

        await _host.Sessions.EndAllAsync();

        (await statuses.WaitAsync(s => s.State == SkakelLinkState.Failed)).Failure!.Kind.Should().Be(SkakelFailureKind.ServerStopping);
        await statuses.WaitAsync(_ => statuses.Seen.Count(s => s.State == SkakelLinkState.Connected) == 2);
        link.Status.State.Should().Be(SkakelLinkState.Connected);
    }

    [Fact]
    public async Task StopAsync_closes_the_hub_and_says_so()
    {
        var (link, _) = await _host.LinkAsync();
        await using var __ = link;
        var statuses = Record(link);
        link.Start();
        await statuses.WaitAsync(s => s.State == SkakelLinkState.Connected);

        await link.StopAsync();

        link.Status.State.Should().Be(SkakelLinkState.Stopped);
        statuses.Seen[^1].State.Should().Be(SkakelLinkState.Stopped);
    }

    [Fact]
    public async Task CreateHttpClient_sends_the_token_over_the_pinned_handler()
    {
        var (link, credentials) = await _host.LinkAsync();
        await using var _ = link;
        using var http = link.CreateHttpClient();

        var hello = await http.GetStringAsync(new Uri(Skakel.Protocol.SkakelProtocol.HelloPath, UriKind.Relative), TestContext.Current.CancellationToken);

        hello.Should().Contain(credentials.ClientId);
    }

    internal static Recorder<SkakelLinkStatus> Record(SkakelLink link)
    {
        var statuses = new Recorder<SkakelLinkStatus>();
        link.StatusChanged += statuses.Record;
        return statuses;
    }

    private static async Task<SkakelFailure> ShouldFail(Func<Task> call, SkakelFailureKind kind)
    {
        var failure = (await call.Should().ThrowAsync<SkakelException>()).Which.Failure;
        failure.Kind.Should().Be(kind);
        return failure;
    }
}
