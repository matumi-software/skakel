using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Skakel.Protocol;

namespace Skakel.Client.Tests;

/// <summary>Reading a server's info with the limits discovery applies, against servers that break them.</summary>
public sealed class InfoTests
{
    [Fact]
    public async Task ReadAsync_refuses_an_answer_over_64_KB()
    {
        await using var fake = await FakeServer.StartAsync(app => app.MapGet(SkakelProtocol.InfoPath, () => FakeServer.Info(new string('A', 1024 * 1024))));

        var read = () => SkakelInfoClient.ReadAsync(fake.Address, fake.Pins, cancellationToken: TestContext.Current.CancellationToken);

        (await read.Should().ThrowAsync<SkakelException>()).Which.Failure.Kind.Should().Be(SkakelFailureKind.UnexpectedAnswer);
    }

    [Fact]
    public async Task ReadAsync_cleans_the_name_and_cuts_it_to_63_characters()
    {
        await using var fake = await FakeServer.StartAsync(app => app.MapGet(SkakelProtocol.InfoPath, () => FakeServer.Info("\u202Epi\u200B-lab\n" + new string('x', 100))));

        var info = await SkakelInfoClient.ReadAsync(fake.Address, fake.Pins, cancellationToken: TestContext.Current.CancellationToken);

        info.Name.Should().Be("pi-lab" + new string('x', 57));
    }

    [Fact]
    public async Task ReadAsync_names_a_server_by_its_address_when_its_name_cleans_to_nothing()
    {
        await using var fake = await FakeServer.StartAsync(app => app.MapGet(SkakelProtocol.InfoPath, () => FakeServer.Info("\u202E\u200B")));

        var info = await SkakelInfoClient.ReadAsync(fake.Address, fake.Pins, cancellationToken: TestContext.Current.CancellationToken);

        info.Name.Should().Be("127.0.0.1");
    }

    [Theory]
    [InlineData("Koppel", "1")]
    [InlineData("", "1")]
    [InlineData("koppel", "123456789012345678901234567890123")]
    public async Task ReadAsync_refuses_an_app_id_that_is_not_one_or_a_long_version(string id, string version)
    {
        await using var fake = await FakeServer.StartAsync(app => app.MapGet(SkakelProtocol.InfoPath, () =>
            Results.Json(new SkakelInfo("fake", new SkakelApp(id, version), [1]), SkakelJson.Options)));

        var read = () => SkakelInfoClient.ReadAsync(fake.Address, fake.Pins, cancellationToken: TestContext.Current.CancellationToken);

        (await read.Should().ThrowAsync<SkakelException>()).Which.Failure.Kind.Should().Be(SkakelFailureKind.UnexpectedAnswer);
    }
}
