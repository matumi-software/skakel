using System.Text.Json;
using Microsoft.AspNetCore.SignalR.Client;
using Skakel.Protocol;

namespace Skakel.Server.Tests;

/// <summary>Replacing the certificate in a handover over the hub: prepare, the clients store it, switch or cancel.</summary>
public sealed class CertificateHandoverTests : IAsyncLifetime
{
    private SkakelTestHost _host = null!;

    public async ValueTask InitializeAsync() => _host = await SkakelTestHost.StartAsync();

    public ValueTask DisposeAsync() => _host.DisposeAsync();

    [Fact]
    public async Task A_handover_tells_the_hub_who_has_the_next_certificate_and_switches()
    {
        var ct = TestContext.Current.CancellationToken;
        var (bench1, token) = await _host.NewClientWithTokenAsync("bench-1", ct);
        await _host.Clients.RegisterAsync("bench-2", ct);
        var hub = await _host.ConnectHubAsync(token, ct);
        await using var connection = hub.Connection;
        var current = _host.Keys.Fingerprint;
        await hub.CertificatesAsync(c => c.GetProperty("fingerprint").GetString() == current, ct);
        var received = new TaskCompletionSource<IReadOnlyList<SkakelClientView>>();
        _host.Clients.Changed += clients =>
        {
            if (clients.Any(c => c.HasNextCertificate))
            {
                received.TrySetResult(clients);
            }

            return Task.CompletedTask;
        };

        var next = await _host.Keys.PrepareNextCertificateAsync(ct);

        next.Should().NotBeNull().And.NotBe(current);
        _host.Keys.Fingerprint.Should().Be(current, "the server goes on presenting the current one");
        (await _host.Keys.PrepareNextCertificateAsync(ct)).Should().BeNull("one is already prepared");
        var told = await hub.CertificatesAsync(c => c.GetProperty("nextFingerprint").GetString() == next, ct);
        told.GetProperty("fingerprint").GetString().Should().Be(current);

        await connection.InvokeAsync(SkakelHubMethods.NextCertificateReceived, next!.Replace(":", "", StringComparison.Ordinal).ToLowerInvariant(), ct);
        (await received.Task.WaitAsync(TimeSpan.FromSeconds(10), ct)).Single(c => c.HasNextCertificate).Id.Should().Be(bench1.ClientId);

        var switched = await _host.Keys.SwitchCertificateAsync(ct);

        switched.Should().BeEquivalentTo(new SkakelCertificateSwitch(current, next, ["bench-2"]));
        Fingerprints.Of(_host.Keys.Certificate).Should().Be(next);
        _host.Keys.NextFingerprint.Should().BeNull();
        var after = await hub.CertificatesAsync(c => c.GetProperty("fingerprint").GetString() == next, ct);
        after.GetProperty("nextFingerprint").ValueKind.Should().Be(JsonValueKind.Null);
        _host.Clients.All.Should().OnlyContain(c => !c.HasNextCertificate);
        (await _host.Keys.SwitchCertificateAsync(ct)).Should().BeNull("nothing is prepared any more");
    }

    [Fact]
    public async Task Cancelling_tells_the_hub_to_forget_the_next_certificate()
    {
        var ct = TestContext.Current.CancellationToken;
        var (_, token) = await _host.NewClientWithTokenAsync("bench-1", ct);
        var hub = await _host.ConnectHubAsync(token, ct);
        await using var connection = hub.Connection;
        var next = await _host.Keys.PrepareNextCertificateAsync(ct);
        await hub.CertificatesAsync(c => c.GetProperty("nextFingerprint").GetString() == next, ct);
        var forgotten = hub.CertificatesAsync(c => c.GetProperty("nextFingerprint").ValueKind == JsonValueKind.Null && c.GetProperty("fingerprint").GetString() == _host.Keys.Fingerprint, ct);

        (await _host.Keys.CancelNextCertificateAsync(ct)).Should().BeTrue();

        await forgotten;
        _host.Keys.NextFingerprint.Should().BeNull();
        (await _host.Keys.CancelNextCertificateAsync(ct)).Should().BeFalse();
    }

    [Fact]
    public async Task A_client_that_connects_during_a_handover_is_told_on_connect()
    {
        var ct = TestContext.Current.CancellationToken;
        var (_, token) = await _host.NewClientWithTokenAsync("bench-1", ct);
        var next = await _host.Keys.PrepareNextCertificateAsync(ct);

        var hub = await _host.ConnectHubAsync(token, ct);
        await using var connection = hub.Connection;

        await hub.CertificatesAsync(c => c.GetProperty("nextFingerprint").GetString() == next, ct);
    }

    [Fact]
    public async Task A_next_certificate_received_that_is_not_the_prepared_one_is_ignored()
    {
        var ct = TestContext.Current.CancellationToken;
        var (_, token) = await _host.NewClientWithTokenAsync("bench-1", ct);
        await _host.Keys.PrepareNextCertificateAsync(ct);
        var hub = await _host.ConnectHubAsync(token, ct);
        await using var connection = hub.Connection;

        await connection.InvokeAsync(SkakelHubMethods.NextCertificateReceived, _host.Keys.Fingerprint, ct);

        _host.Clients.All.Single().HasNextCertificate.Should().BeFalse();
    }

    [Fact]
    public async Task The_handover_survives_a_restart()
    {
        var ct = TestContext.Current.CancellationToken;
        var current = _host.Keys.Fingerprint;
        var next = await _host.Keys.PrepareNextCertificateAsync(ct);
        await _host.StopAsync();

        await using var restarted = await SkakelTestHost.StartAsync(store: _host.Store);

        restarted.Keys.Fingerprint.Should().Be(current);
        restarted.Keys.NextFingerprint.Should().Be(next);
    }
}
