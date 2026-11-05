namespace Skakel.Client.Tests;

/// <summary>Tokens renewed before they run out, the hub renewed with them unseen, and the certificate handover.</summary>
public sealed class HandoverTests : IAsyncLifetime
{
    private SkakelHost _host = null!;

    public async ValueTask InitializeAsync() => _host = await SkakelHost.StartAsync();

    public ValueTask DisposeAsync() => _host.DisposeAsync();

    [Fact]
    public async Task GetAsync_reuses_a_token_until_a_minute_before_it_runs_out()
    {
        var ct = TestContext.Current.CancellationToken;
        var time = new ManualTimeProvider();
        var credentials = await _host.RegisterAsync();
        using var handler = Pinning.CreateHandler(() => _host.Pins);
        using var http = new HttpClient(handler);
        using var tokens = new TokenClient(http, () => _host.Address, credentials, time);

        var first = await tokens.GetAsync(ct);
        first.ExpiresAt.Should().BeCloseTo(time.GetUtcNow().AddMinutes(30), TimeSpan.FromSeconds(5));
        time.Advance(first.ExpiresAt - time.GetUtcNow() - TimeSpan.FromSeconds(61));
        (await tokens.GetAsync(ct)).Token.Should().Be(first.Token);

        time.Advance(TimeSpan.FromSeconds(2));
        var renewed = await tokens.GetAsync(ct);

        renewed.Token.Should().NotBe(first.Token);
        renewed.ExpiresAt.Should().BeAfter(first.ExpiresAt);
    }

    [Fact]
    public async Task The_hub_connects_again_with_a_fresh_token_before_it_runs_out_without_saying_so()
    {
        var ct = TestContext.Current.CancellationToken;
        var time = new ManualTimeProvider();
        var (link, _) = await _host.LinkAsync(new SkakelClientOptions { TimeProvider = time });
        await using var __ = link;
        var statuses = LinkTests.Record(link);
        link.Start();
        await statuses.WaitAsync(s => s.State == SkakelLinkState.Connected);
        var connection = await link.InvokeAsync<string>(nameof(TestHub.Connection), cancellationToken: ct);
        var token = await link.GetAccessTokenAsync(ct);
        await time.WhenTimersAsync(1);

        time.Advance(TimeSpan.FromMinutes(29) + TimeSpan.FromSeconds(31));

        string renewed;
        do
        {
            await Task.Delay(20, ct);
            renewed = await link.InvokeAsync<string>(nameof(TestHub.Connection), cancellationToken: ct);
        }
        while (renewed == connection);

        (await link.GetAccessTokenAsync(ct)).Should().NotBe(token, "the new connection took a fresh token");
        statuses.Seen.Select(s => s.State).Should().Equal([SkakelLinkState.Connecting, SkakelLinkState.Connected], "a renewal is not a change anyone hears of");
    }

    [Fact]
    public async Task A_handover_is_learned_over_the_hub_saved_by_the_app_and_acknowledged()
    {
        var ct = TestContext.Current.CancellationToken;
        var (link, credentials) = await _host.LinkAsync();
        await using var _ = link;
        var pins = new Recorder<SkakelPins>();
        link.PinsChanged += pins.Record;
        var statuses = LinkTests.Record(link);
        var acknowledged = new TaskCompletionSource();
        _host.Clients.Changed += clients =>
        {
            if (clients.Any(c => c.Id == credentials.ClientId && c.HasNextCertificate))
            {
                acknowledged.TrySetResult();
            }

            return Task.CompletedTask;
        };
        link.Start();
        await statuses.WaitAsync(s => s.State == SkakelLinkState.Connected);
        var current = _host.Keys.Fingerprint;

        var next = await _host.Keys.PrepareNextCertificateAsync(ct);

        (await pins.WaitAsync(p => p.NextFingerprint == next)).Fingerprint.Should().Be(current);
        await acknowledged.Task.WaitAsync(TimeSpan.FromSeconds(15), ct);

        (await _host.Keys.SwitchCertificateAsync(ct))!.NotReceived.Should().BeEmpty();

        await pins.WaitAsync(p => p.Fingerprint == next && p.NextFingerprint is null);
        link.Pins.Should().Be(new SkakelPins(next!));

        // New connections get the new certificate: the learned pins reach it, the old pin alone does not.
        await using var learned = new SkakelLink(_host.Address, link.Pins, credentials);
        (await learned.HelloAsync(ct)).ClientId.Should().Be(credentials.ClientId);
        await using var stale = new SkakelLink(_host.Address, new SkakelPins(current), credentials);
        var hello = () => stale.HelloAsync(ct);
        (await hello.Should().ThrowAsync<SkakelException>()).Which.Failure.Kind.Should().Be(SkakelFailureKind.CertificateMismatch);

        // And the link itself connects again across the switch.
        await link.StopAsync();
        var again = LinkTests.Record(link);
        link.Start();
        await again.WaitAsync(s => s.State == SkakelLinkState.Connected);
    }

    [Fact]
    public async Task A_cancelled_handover_is_forgotten()
    {
        var ct = TestContext.Current.CancellationToken;
        var (link, _) = await _host.LinkAsync();
        await using var __ = link;
        var pins = new Recorder<SkakelPins>();
        link.PinsChanged += pins.Record;
        var statuses = LinkTests.Record(link);
        link.Start();
        await statuses.WaitAsync(s => s.State == SkakelLinkState.Connected);
        var next = await _host.Keys.PrepareNextCertificateAsync(ct);
        await pins.WaitAsync(p => p.NextFingerprint == next);

        await _host.Keys.CancelNextCertificateAsync(ct);

        await pins.WaitAsync(p => p.NextFingerprint is null);
        link.Pins.Should().Be(new SkakelPins(_host.Keys.Fingerprint));
    }

    [Fact]
    public async Task A_handover_the_app_could_not_save_is_not_acknowledged()
    {
        var ct = TestContext.Current.CancellationToken;
        var (link, credentials) = await _host.LinkAsync();
        await using var _ = link;
        var tried = new TaskCompletionSource();
        link.PinsChanged += _ =>
        {
            tried.TrySetResult();
            throw new IOException("disk full");
        };
        var statuses = LinkTests.Record(link);
        link.Start();
        await statuses.WaitAsync(s => s.State == SkakelLinkState.Connected);

        await _host.Keys.PrepareNextCertificateAsync(ct);
        await tried.Task.WaitAsync(TimeSpan.FromSeconds(15), ct);
        // A call after the handler: the hub runs a connection's messages in order, so an acknowledgement would be in by now.
        await link.InvokeAsync<string>(nameof(TestHub.Echo), ["x"], ct);

        _host.Clients.All.Single(c => c.Id == credentials.ClientId).HasNextCertificate.Should().BeFalse();
    }
}
