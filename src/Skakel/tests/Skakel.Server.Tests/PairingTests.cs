using System.Net;
using System.Net.Http.Json;
using Skakel.Protocol;

namespace Skakel.Server.Tests;

/// <summary>Pairing over HTTP, as a client runs it, with a person typing the code through the app's UI.</summary>
public sealed class PairingTests : IAsyncLifetime
{
    private SkakelTestHost _host = null!;

    public async ValueTask InitializeAsync() => _host = await SkakelTestHost.StartAsync();

    public ValueTask DisposeAsync() => _host.DisposeAsync();

    [Fact]
    public async Task Pairing_with_the_right_code_hands_the_client_credentials_that_get_a_token()
    {
        var ct = TestContext.Current.CancellationToken;
        using var https = _host.Https();
        var pairingChanged = new List<SkakelPairingOverview>();
        _host.Pairing.Changed += overview =>
        {
            pairingChanged.Add(overview);
            return Task.CompletedTask;
        };
        var decided = new TaskCompletionSource<SkakelPairingDecision>();
        _host.Pairing.Decided += decision =>
        {
            decided.TrySetResult(decision);
            return Task.CompletedTask;
        };

        var nonce = PairingCode.NewNonce();
        using var open = await https.PostAsJsonAsync(SkakelProtocol.PairPath, new PairOpenRequest("  bench-2  ", PairingCode.Commit(nonce)), SkakelJson.Options, ct);
        open.StatusCode.Should().Be(HttpStatusCode.OK);
        var opened = (await open.Content.ReadFromJsonAsync<PairOpened>(SkakelJson.Options, ct))!;
        _host.Pairing.Overview.Requests.Should().BeEmpty("nobody can see a request before its client revealed");

        using var reveal = await https.PostAsJsonAsync($"{SkakelProtocol.PairPath}/{opened.RequestId}/reveal", new PairRevealRequest(nonce), SkakelJson.Options, ct);
        reveal.StatusCode.Should().Be(HttpStatusCode.NoContent);
        var waiting = _host.Pairing.Overview.Requests.Should().ContainSingle().Subject;
        waiting.ClientName.Should().Be("bench-2");
        pairingChanged.Should().ContainSingle(o => o.Requests.Count == 1);
        (await PollAsync(https, opened, ct)).Should().Be(new PairPoll(PairStates.Waiting));

        // The client shows the code; the person types it on the server.
        var code = PairingCode.Compute(_host.Keys.Fingerprint, nonce, opened.ServerNonce);
        (await _host.Pairing.ApproveAsync(waiting.Id, code, ct)).Should().Be(SkakelApproval.Approved);

        var approved = (await PollAsync(https, opened, ct))!;
        approved.State.Should().Be(PairStates.Approved);
        approved.ClientId.Should().Be(_host.Clients.All.Single().Id);
        (await PollAsync(https, opened, ct)).Should().BeNull("the credentials are handed over once");
        (await decided.Task).ClientId.Should().Be(approved.ClientId);
        var token = await _host.TokenAsync(approved.ClientId!, approved.ClientSecret!, ct);
        (await _host.HelloAsync(token, ct)).StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Three_wrong_codes_deny_the_request_and_the_client_hears_it()
    {
        var ct = TestContext.Current.CancellationToken;
        using var https = _host.Https();
        var (opened, code) = await OpenAndRevealAsync(https, ct);
        var wrong = code == "000000" ? "111111" : "000000";

        (await _host.Pairing.ApproveAsync(opened.RequestId, wrong, ct)).Should().Be(SkakelApproval.WrongCode);
        (await _host.Pairing.ApproveAsync(opened.RequestId, wrong, ct)).Should().Be(SkakelApproval.WrongCode);
        (await _host.Pairing.ApproveAsync(opened.RequestId, wrong, ct)).Should().Be(SkakelApproval.WrongCode);

        (await _host.Pairing.ApproveAsync(opened.RequestId, code, ct)).Should().Be(SkakelApproval.NotWaiting, "the right code is too late");
        (await PollAsync(https, opened, ct))!.State.Should().Be(PairStates.Denied);
        _host.Clients.All.Should().BeEmpty();
    }

    [Fact]
    public async Task Poll_and_withdraw_need_the_poll_token()
    {
        var ct = TestContext.Current.CancellationToken;
        using var https = _host.Https();
        var (opened, _) = await OpenAndRevealAsync(https, ct);
        var path = $"{SkakelProtocol.PairPath}/{opened.RequestId}";

        (await https.GetAsync(path, ct)).StatusCode.Should().Be(HttpStatusCode.NotFound);
        using var wrongWithdraw = new HttpRequestMessage(HttpMethod.Delete, path) { Headers = { { SkakelProtocol.PairTokenHeader, new string('0', 64) } } };
        (await https.SendAsync(wrongWithdraw, ct)).StatusCode.Should().Be(HttpStatusCode.NotFound);

        using var withdraw = new HttpRequestMessage(HttpMethod.Delete, path) { Headers = { { SkakelProtocol.PairTokenHeader, opened.PollToken } } };
        (await https.SendAsync(withdraw, ct)).StatusCode.Should().Be(HttpStatusCode.NoContent);
        _host.Pairing.Overview.Requests.Should().BeEmpty();
    }

    [Fact]
    public async Task Reveal_refuses_a_nonce_the_commitment_was_not_made_from()
    {
        var ct = TestContext.Current.CancellationToken;
        using var https = _host.Https();
        using var open = await https.PostAsJsonAsync(SkakelProtocol.PairPath, new PairOpenRequest("bench", PairingCode.Commit(PairingCode.NewNonce())), SkakelJson.Options, ct);
        var opened = (await open.Content.ReadFromJsonAsync<PairOpened>(SkakelJson.Options, ct))!;

        using var reveal = await https.PostAsJsonAsync($"{SkakelProtocol.PairPath}/{opened.RequestId}/reveal", new PairRevealRequest(PairingCode.NewNonce()), SkakelJson.Options, ct);

        reveal.StatusCode.Should().Be(HttpStatusCode.NotFound);
        _host.Pairing.Overview.Requests.Should().BeEmpty();
    }

    [Theory]
    [InlineData("", true)]
    [InlineData("   ", true)]
    [InlineData("bench", false)]
    public async Task Open_refuses_a_name_or_commitment_outside_the_rules(string name, bool badName)
    {
        var ct = TestContext.Current.CancellationToken;
        using var https = _host.Https();
        var commitment = badName ? PairingCode.Commit("n") : "not hex";

        using var response = await https.PostAsJsonAsync(SkakelProtocol.PairPath, new PairOpenRequest(name, commitment), SkakelJson.Options, ct);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        response.Content.Headers.ContentType!.MediaType.Should().Be(SkakelProtocol.ProblemContentType);
    }

    [Fact]
    public async Task Open_refuses_a_name_over_80_characters()
    {
        var ct = TestContext.Current.CancellationToken;
        using var https = _host.Https();

        using var response = await https.PostAsJsonAsync(SkakelProtocol.PairPath, new PairOpenRequest(new string('n', 81), PairingCode.Commit("n")), SkakelJson.Options, ct);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Pairing_is_refused_over_plain_http()
    {
        var ct = TestContext.Current.CancellationToken;
        using var http = _host.PlainHttp();

        using var response = await http.PostAsJsonAsync(SkakelProtocol.PairPath, new PairOpenRequest("bench", PairingCode.Commit("n")), SkakelJson.Options, ct);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task An_address_over_its_share_of_opens_gets_429()
    {
        var ct = TestContext.Current.CancellationToken;
        using var https = _host.Https();
        for (var i = 0; i < SkakelPairing.MaxOpenPerAddress; i++)
        {
            (await https.PostAsJsonAsync(SkakelProtocol.PairPath, new PairOpenRequest("bench", PairingCode.Commit($"n{i}")), SkakelJson.Options, ct)).StatusCode.Should().Be(HttpStatusCode.OK);
        }

        using var refused = await https.PostAsJsonAsync(SkakelProtocol.PairPath, new PairOpenRequest("bench", PairingCode.Commit("n")), SkakelJson.Options, ct);

        refused.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);
    }

    [Fact]
    public async Task Info_answers_the_name_the_app_and_the_versions_without_a_token()
    {
        var ct = TestContext.Current.CancellationToken;
        using var https = _host.Https();

        var info = await https.GetFromJsonAsync<SkakelInfo>(SkakelProtocol.InfoPath, SkakelJson.Options, ct);

        info.Should().BeEquivalentTo(new SkakelInfo("bench", new SkakelApp("test-app", "1.2.3"), [1]));
    }

    private async Task<(PairOpened Opened, string Code)> OpenAndRevealAsync(HttpClient https, CancellationToken ct)
    {
        var nonce = PairingCode.NewNonce();
        using var open = await https.PostAsJsonAsync(SkakelProtocol.PairPath, new PairOpenRequest("bench", PairingCode.Commit(nonce)), SkakelJson.Options, ct);
        var opened = (await open.Content.ReadFromJsonAsync<PairOpened>(SkakelJson.Options, ct))!;
        using var reveal = await https.PostAsJsonAsync($"{SkakelProtocol.PairPath}/{opened.RequestId}/reveal", new PairRevealRequest(nonce), SkakelJson.Options, ct);
        reveal.EnsureSuccessStatusCode();
        return (opened, PairingCode.Compute(_host.Keys.Fingerprint, nonce, opened.ServerNonce));
    }

    private static async Task<PairPoll?> PollAsync(HttpClient https, PairOpened opened, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"{SkakelProtocol.PairPath}/{opened.RequestId}");
        request.Headers.Add(SkakelProtocol.PairTokenHeader, opened.PollToken);
        using var response = await https.SendAsync(request, ct);
        return response.StatusCode == HttpStatusCode.NotFound ? null : await response.Content.ReadFromJsonAsync<PairPoll>(SkakelJson.Options, ct);
    }
}
