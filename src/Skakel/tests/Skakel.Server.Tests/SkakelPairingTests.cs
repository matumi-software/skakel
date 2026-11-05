using System.Net;
using System.Reflection;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Skakel.Protocol;

namespace Skakel.Server.Tests;

/// <summary>
/// The server's pairing requests on their own, against a manual clock: who may poll and withdraw,
/// how many requests a server takes, and what concurrent approvals and wrong codes do.
/// </summary>
public sealed class SkakelPairingTests : IAsyncLifetime
{
    private readonly ManualTimeProvider _time = new();
    private ServerState _state = null!;
    private SkakelPairing _store = null!;

    public async ValueTask InitializeAsync()
    {
        _state = new ServerState(new InMemorySkakelStore(), Options.Create(new SkakelServerOptions { AppId = "test-app", AppVersion = "1", Port = 5240 }), _time, NullLogger<ServerState>.Instance);
        await _state.StartAsync(TestContext.Current.CancellationToken);
        _store = new SkakelPairing(_state, _time, NullLogger<SkakelPairing>.Instance);
    }

    public ValueTask DisposeAsync()
    {
        _store.Dispose();
        _state.Dispose();
        return ValueTask.CompletedTask;
    }

    [Fact]
    public async Task Poll_and_withdraw_need_the_token_the_open_reply_carried()
    {
        var (opened, _) = await OpenAndRevealAsync();

        (await _store.PollAsync(opened.RequestId, null)).Should().BeNull();
        (await _store.PollAsync(opened.RequestId, "")).Should().BeNull();
        (await _store.PollAsync(opened.RequestId, new string('0', opened.PollToken.Length))).Should().BeNull();
        (await _store.WithdrawAsync(opened.RequestId, null)).Should().BeFalse();
        (await _store.WithdrawAsync(opened.RequestId, "wrong")).Should().BeFalse();
        _store.Pending.Should().HaveCount(1, "a refused withdraw leaves the request where it was");

        (await _store.PollAsync(opened.RequestId, opened.PollToken))!.State.Should().Be("waiting");
        (await _store.WithdrawAsync(opened.RequestId, opened.PollToken)).Should().BeTrue();
        _store.Pending.Should().BeEmpty();
    }

    [Fact]
    public async Task The_poll_token_is_random_per_request_and_never_in_what_the_ui_sees()
    {
        var (first, _) = await OpenAndRevealAsync(Address(1000));
        var (second, _) = await OpenAndRevealAsync(Address(1001));

        first.PollToken.Should().NotBe(second.PollToken);
        first.PollToken.Should().HaveLength(64, "32 random bytes as hex");
        var pushed = JsonSerializer.Serialize(_store.Pending);
        pushed.Should().NotContain(first.PollToken).And.NotContain(second.PollToken);
        typeof(SkakelPairingRequest).GetProperties().Select(p => p.Name).Should().NotContain(n => n.Contains("Token", StringComparison.Ordinal));
    }

    [Fact]
    public async Task The_server_takes_a_fixed_number_of_revealed_requests_per_window_and_withdrawing_does_not_give_them_back()
    {
        for (var i = 0; i < SkakelPairing.RevealsPerWindow; i++)
        {
            var (opened, _) = await OpenAndRevealAsync(Address(i));
            (await _store.WithdrawAsync(opened.RequestId, opened.PollToken)).Should().BeTrue();
        }

        _store.Open("bench", Commitment(), Address(99)).Should().BeNull("nothing is open, yet the budget is spent");

        _time.Advance(SkakelPairing.OpenWindow);

        _store.Open("bench", Commitment(), Address(99)).Should().NotBeNull("the window moved on");
    }

    [Fact]
    public async Task One_address_cannot_use_up_what_the_others_need()
    {
        var noisy = Address(1);
        for (var i = 0; i < SkakelPairing.OpensPerAddressPerWindow; i++)
        {
            var opened = _store.Open("noisy", Commitment(), noisy);
            opened.Should().NotBeNull();
            await _store.WithdrawAsync(opened!.RequestId, opened.PollToken);
        }

        _store.Open("noisy", Commitment(), noisy).Should().BeNull("that address spent its share");
        _store.Open("quiet", Commitment(), Address(2)).Should().NotBeNull("the others still have theirs");
        _store.BudgetExhausted.Should().BeFalse("one address spending its share is not the server running out");

        _time.Advance(SkakelPairing.OpenWindow);

        _store.Open("noisy", Commitment(), noisy).Should().NotBeNull("the share comes back with the window");
    }

    [Fact]
    public async Task Each_ipv6_address_has_its_own_share_of_the_budget()
    {
        var noisy = IPAddress.Parse("2001:db8:1:1::1");
        for (var i = 0; i < SkakelPairing.OpensPerAddressPerWindow; i++)
        {
            var opened = _store.Open("v6", Commitment(), noisy);
            opened.Should().NotBeNull();
            await _store.WithdrawAsync(opened!.RequestId, opened.PollToken);
        }

        _store.Open("v6", Commitment(), noisy).Should().BeNull();
        _store.Open("v6", Commitment(), IPAddress.Parse("2001:db8:1:1::2")).Should().NotBeNull("another host on the same /64 has its own share");
        _store.Open("v6", Commitment(), IPAddress.Parse("fe80::2")).Should().NotBeNull();
    }

    [Fact]
    public async Task The_ceiling_for_the_whole_server_holds_however_many_addresses_ask()
    {
        var early = _store.Open("early", PairingCode.Commit("early"), Address(499))!;
        await SpendTheCeilingAsync();

        _store.Open("one more", Commitment(), Address(500)).Should().BeNull("every address is fresh, the server is out");
        _store.BudgetExhausted.Should().BeTrue();
        (await _store.RevealAsync(early.RequestId, "early")).Should().Be(SkakelReveal.Full, "a request opened before the ceiling was spent cannot reveal past it");
    }

    [Fact]
    public async Task The_ui_is_told_when_the_budget_runs_out_and_when_it_comes_back()
    {
        var pushed = new List<bool>();
        _store.Changed += overview =>
        {
            pushed.Add(overview.BudgetExhausted);
            return Task.CompletedTask;
        };
        _store.Overview.BudgetExhausted.Should().BeFalse();

        await SpendTheCeilingAsync();

        _store.Overview.BudgetExhausted.Should().BeTrue();
        _time.Advance(SkakelPairing.SweepInterval);
        pushed.Should().EndWith(true);

        _time.Advance(SkakelPairing.OpenWindow);

        _store.Overview.BudgetExhausted.Should().BeFalse();
        pushed.Should().EndWith(false);
    }

    [Fact]
    public void Requests_nobody_can_see_yet_do_not_count_against_the_cap()
    {
        for (var i = 0; i < SkakelPairing.MaxOpen; i++)
        {
            _store.Open("hidden", Commitment(), Address(i)).Should().NotBeNull();
        }

        _store.Open("eleventh", Commitment(), Address(50)).Should().NotBeNull("unrevealed requests are not waiting for anyone");
    }

    [Fact]
    public async Task Requests_a_person_can_see_count_against_the_cap()
    {
        for (var i = 0; i < SkakelPairing.MaxOpen; i++)
        {
            await OpenAndRevealAsync(Address(100 + i));
        }

        _store.Open("one too many", Commitment(), Address(200)).Should().BeNull();
    }

    [Fact]
    public async Task A_request_that_never_reveals_is_dropped_after_a_short_while()
    {
        var opened = _store.Open("slow", PairingCode.Commit("n"), IPAddress.Parse("10.0.0.1"))!;

        _time.Advance(SkakelPairing.UnrevealedLifetime + TimeSpan.FromSeconds(1));

        (await _store.RevealAsync(opened.RequestId, "n")).Should().Be(SkakelReveal.NotFound);
        (await _store.PollAsync(opened.RequestId, opened.PollToken)).Should().BeNull("the sweep removed it");
    }

    [Fact]
    public void Addresses_count_per_whole_address()
    {
        var one = IPAddress.Parse("2001:db8:1:1::1");
        for (var i = 0; i < SkakelPairing.MaxOpenPerAddress; i++)
        {
            _store.Open("v6", Commitment(), one).Should().NotBeNull();
        }

        _store.Open("v6", Commitment(), one).Should().BeNull();
        _store.Open("v6", Commitment(), IPAddress.Parse("2001:db8:1:1::2")).Should().NotBeNull("same /64, another host");
        _store.Open("v4", Commitment(), IPAddress.Parse("10.0.0.1")).Should().NotBeNull();
        SkakelPairing.AddressKey(one).Should().NotBe(SkakelPairing.AddressKey(IPAddress.Parse("2001:db8:1:1:aaaa:bbbb:cccc:dddd")));
        SkakelPairing.AddressKey(IPAddress.Parse("fe80::1")).Should().NotBe(SkakelPairing.AddressKey(IPAddress.Parse("fe80::2")));
        SkakelPairing.AddressKey(IPAddress.Parse("::ffff:10.0.0.1")).Should().Be(SkakelPairing.AddressKey(IPAddress.Parse("10.0.0.1")));
    }

    [Fact]
    public async Task Two_people_approving_at_once_make_one_client()
    {
        var (opened, code) = await OpenAndRevealAsync();

        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(() => _store.ApproveAsync(opened.RequestId, code, CancellationToken.None))));

        results.Count(r => r == SkakelApproval.Approved).Should().Be(1);
        results.Count(r => r == SkakelApproval.NotWaiting).Should().Be(7, "the request is no longer waiting");
        _state.Clients.Should().HaveCount(1);
        var poll = (await _store.PollAsync(opened.RequestId, opened.PollToken))!;
        poll.State.Should().Be("approved");
        poll.ClientId.Should().Be(_state.Clients[0].Id);
        poll.ClientSecret.Should().NotBeNullOrEmpty();
        (await _store.PollAsync(opened.RequestId, opened.PollToken)).Should().BeNull("credentials are handed over once");
    }

    [Fact]
    public async Task Wrong_codes_typed_at_once_are_all_counted()
    {
        var (opened, code) = await OpenAndRevealAsync();
        var wrong = code == "000000" ? "111111" : "000000";

        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(() => _store.ApproveAsync(opened.RequestId, wrong, CancellationToken.None))));

        results.Count(r => r == SkakelApproval.WrongCode).Should().Be(SkakelPairing.MaxWrongCodes, "no count lost and none past the limit");
        results.Count(r => r == SkakelApproval.NotWaiting).Should().Be(8 - SkakelPairing.MaxWrongCodes);
        (await _store.ApproveAsync(opened.RequestId, code, CancellationToken.None)).Should().Be(SkakelApproval.NotWaiting, "the right code is too late");
        _state.Clients.Should().BeEmpty();
    }

    [Fact]
    public async Task A_request_that_runs_out_of_time_leaves_the_list_and_the_ui_is_told_without_anyone_calling()
    {
        await OpenAndRevealAsync();
        var pushes = new List<int>();
        _store.Changed += list =>
        {
            pushes.Add(list.Requests.Count);
            return Task.CompletedTask;
        };

        _time.Advance(SkakelPairing.Lifetime + SkakelPairing.SweepInterval);

        pushes.Should().Contain(0);
        _store.Pending.Should().BeEmpty();
    }

    [Fact]
    public async Task Three_wrong_codes_keep_the_request_listed_as_denied_for_a_moment()
    {
        var (opened, code) = await OpenAndRevealAsync();
        var wrong = code == "000000" ? "111111" : "000000";
        var pushed = new List<IReadOnlyList<SkakelPairingRequest>>();
        _store.Changed += list =>
        {
            pushed.Add(list.Requests);
            return Task.CompletedTask;
        };

        for (var i = 0; i < SkakelPairing.MaxWrongCodes; i++)
        {
            await _store.ApproveAsync(opened.RequestId, wrong, CancellationToken.None);
        }

        var view = _store.Pending.Should().ContainSingle().Subject;
        view.State.Should().Be("denied");
        view.Message.Should().Contain("wrong three times");
        pushed.Last().Should().ContainSingle(v => v.State == "denied");
        (await _store.PollAsync(opened.RequestId, opened.PollToken))!.State.Should().Be("denied", "the client hears it too");

        _time.Advance(SkakelPairing.DeniedVisibleFor + SkakelPairing.SweepInterval);

        _store.Pending.Should().BeEmpty();
        pushed.Last().Should().BeEmpty("the list is pushed again once the denied entry goes");
    }

    [Fact]
    public async Task Refusing_a_request_takes_it_off_the_list_at_once()
    {
        var (opened, _) = await OpenAndRevealAsync();

        (await _store.DenyAsync(opened.RequestId)).Should().BeTrue();

        _store.Pending.Should().BeEmpty();
        (await _store.PollAsync(opened.RequestId, opened.PollToken))!.State.Should().Be("denied");
    }

    [Fact]
    public async Task Two_polls_at_once_hand_the_credentials_over_once()
    {
        var (opened, code) = await OpenAndRevealAsync();
        (await _store.ApproveAsync(opened.RequestId, code, CancellationToken.None)).Should().Be(SkakelApproval.Approved);

        var gate = GateOf(opened.RequestId);
        await gate.WaitAsync(TestContext.Current.CancellationToken);
        var first = _store.PollAsync(opened.RequestId, opened.PollToken);
        var second = _store.PollAsync(opened.RequestId, opened.PollToken);
        gate.Release();
        var polls = await Task.WhenAll(first, second);

        polls.Count(p => p?.ClientSecret is not null).Should().Be(1);
        polls.Count(p => p is null).Should().Be(1, "the second poll finds the request gone");
    }

    [Fact]
    public async Task A_request_withdrawn_while_a_person_approves_it_registers_nobody()
    {
        var (opened, code) = await OpenAndRevealAsync();

        var gate = GateOf(opened.RequestId);
        await gate.WaitAsync(TestContext.Current.CancellationToken);
        var withdraw = _store.WithdrawAsync(opened.RequestId, opened.PollToken);
        var approve = _store.ApproveAsync(opened.RequestId, code, CancellationToken.None);
        gate.Release();

        (await withdraw).Should().BeTrue();
        (await approve).Should().Be(SkakelApproval.NotWaiting);
        _state.Clients.Should().BeEmpty();
    }

    [Fact]
    public void Opens_that_never_reveal_give_their_place_under_the_ceiling_back()
    {
        for (var i = 0; i < SkakelPairing.RevealsPerWindow; i++)
        {
            _store.Open("silent", Commitment(), Address(i)).Should().NotBeNull();
        }

        _time.Advance(SkakelPairing.UnrevealedLifetime + SkakelPairing.SweepInterval);

        _store.BudgetExhausted.Should().BeFalse("nobody revealed, so nobody could have been fooled");
        _store.Open("legit", Commitment(), Address(200)).Should().NotBeNull();
    }

    /// <summary>The gate a request's state changes wait on, so a test can line calls up behind it.</summary>
    private SemaphoreSlim GateOf(string requestId)
    {
        var requests = (System.Collections.IDictionary)typeof(SkakelPairing).GetField("_requests", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(_store)!;
        var request = requests[requestId]!;
        return (SemaphoreSlim)request.GetType().GetProperty("Gate")!.GetValue(request)!;
    }

    private async Task<(PairOpened Opened, string Code)> OpenAndRevealAsync(IPAddress? address = null)
    {
        var nonce = PairingCode.NewNonce();
        var opened = _store.Open("bench", PairingCode.Commit(nonce), address ?? Address(0))!;
        (await _store.RevealAsync(opened.RequestId, nonce)).Should().Be(SkakelReveal.Revealed);
        return (opened, PairingCode.Compute(_state.Fingerprint, nonce, opened.ServerNonce));
    }

    /// <summary>Reveals as many requests as the window allows, each from its own address, withdrawing each so the cap on waiting requests stays clear.</summary>
    private async Task SpendTheCeilingAsync()
    {
        for (var i = 0; i < SkakelPairing.RevealsPerWindow; i++)
        {
            var (opened, _) = await OpenAndRevealAsync(Address(i));
            (await _store.WithdrawAsync(opened.RequestId, opened.PollToken)).Should().BeTrue();
        }
    }

    private static string Commitment() => PairingCode.Commit(PairingCode.NewNonce());

    private static IPAddress Address(int i) => IPAddress.Parse($"10.1.{i / 250}.{i % 250 + 1}");
}
