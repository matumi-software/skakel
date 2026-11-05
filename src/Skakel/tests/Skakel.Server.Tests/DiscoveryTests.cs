using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.DependencyInjection;
using Skakel.Protocol;

namespace Skakel.Server.Tests;

/// <summary>The server's discovery answers on UDP: what they say, and that they are never larger than the probe.</summary>
public sealed class DiscoveryTests : IAsyncLifetime
{
    private SkakelTestHost _host = null!;
    private UdpClient _udp = null!;
    private IPEndPoint _server = null!;

    public async ValueTask InitializeAsync()
    {
        _host = await SkakelTestHost.StartAsync(o =>
        {
            o.DiscoveryEnabled = true;
            o.DiscoveryPort = 0;
        });
        _server = new IPEndPoint(IPAddress.Loopback, _host.Services.GetRequiredService<SkakelDiscoveryService>().LocalPort!.Value);
        _udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
    }

    public async ValueTask DisposeAsync()
    {
        _udp.Dispose();
        await _host.DisposeAsync();
    }

    [Fact]
    public async Task A_probe_gets_the_name_port_fingerprint_app_and_versions()
    {
        var ct = TestContext.Current.CancellationToken;

        var answer = await ProbeAsync(SkakelDiscovery.CreateProbe(), ct);

        answer.Should().NotBeNull();
        answer!.Length.Should().BeLessThanOrEqualTo(SkakelDiscovery.ProbeSize);
        SkakelDiscovery.TryParseAnswer(answer, out var parsed).Should().BeTrue();
        parsed.Should().BeEquivalentTo(new DiscoveryAnswer("bench", 5240, _host.Keys.Fingerprint, new SkakelApp("test-app", "1.2.3"), [1]));
    }

    [Fact]
    public async Task A_short_probe_or_another_packet_gets_no_answer()
    {
        var ct = TestContext.Current.CancellationToken;
        var wrongLine = new byte[SkakelDiscovery.ProbeSize];
        "KOPPEL-DISCOVER/1\n"u8.CopyTo(wrongLine);

        (await ProbeAsync(SkakelDiscovery.CreateProbe()[..511], ct)).Should().BeNull();
        (await ProbeAsync(wrongLine, ct)).Should().BeNull();
        (await ProbeAsync(SkakelDiscovery.CreateProbe(), ct)).Should().NotBeNull("the server still answers after them");
    }

    [Fact]
    public async Task The_answer_carries_the_new_fingerprint_after_a_switch()
    {
        var ct = TestContext.Current.CancellationToken;
        var next = await _host.Keys.PrepareNextCertificateAsync(ct);
        await _host.Keys.SwitchCertificateAsync(ct);

        var answer = await ProbeAsync(SkakelDiscovery.CreateProbe(), ct);

        SkakelDiscovery.TryParseAnswer(answer!, out var parsed).Should().BeTrue();
        parsed!.Fingerprint.Should().Be(next);
    }

    [Fact]
    public async Task A_probe_from_port_0_gets_no_answer_and_the_server_goes_on_answering()
    {
        var ct = TestContext.Current.CancellationToken;
        var probe = SkakelDiscovery.CreateProbe();
        var datagram = new byte[8 + probe.Length];
        BinaryPrimitives.WriteUInt16BigEndian(datagram.AsSpan(0), 0);
        BinaryPrimitives.WriteUInt16BigEndian(datagram.AsSpan(2), (ushort)_server.Port);
        BinaryPrimitives.WriteUInt16BigEndian(datagram.AsSpan(4), (ushort)datagram.Length);
        probe.CopyTo(datagram, 8);
        try
        {
            // A UDP socket cannot send from port 0, so the datagram is built by hand, checksum left out.
            using var raw = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Udp);
            raw.SendTo(datagram, new IPEndPoint(IPAddress.Loopback, 0));
        }
        catch (SocketException ex)
        {
            Assert.Skip($"Sending a raw UDP datagram is not allowed here: {ex.SocketErrorCode}.");
        }

        await Task.Delay(300, ct);

        (await ProbeAsync(SkakelDiscovery.CreateProbe(), ct)).Should().NotBeNull("one probe the server cannot answer must not stop the answers");
    }

    [Theory]
    [InlineData("192.168.1.20", 50000, true)]
    [InlineData("127.0.0.1", 50000, true)]
    [InlineData("::ffff:10.0.0.5", 50000, true)]
    [InlineData("fe80::1", 50000, true)]
    [InlineData("192.168.1.20", 0, false)]
    [InlineData("0.0.0.0", 50000, false)]
    [InlineData("255.255.255.255", 50000, false)]
    [InlineData("224.0.0.251", 50000, false)]
    [InlineData("::", 50000, false)]
    [InlineData("ff02::1", 50000, false)]
    public void CanAnswer_takes_only_a_unicast_sender_on_a_real_port(string address, int port, bool answered) =>
        SkakelDiscoveryService.CanAnswer(new IPEndPoint(IPAddress.Parse(address), port)).Should().Be(answered);

    private async Task<byte[]?> ProbeAsync(byte[] probe, CancellationToken ct)
    {
        await _udp.SendAsync(probe, _server, ct);
        using var wait = CancellationTokenSource.CreateLinkedTokenSource(ct);
        wait.CancelAfter(TimeSpan.FromSeconds(1));
        try
        {
            return (await _udp.ReceiveAsync(wait.Token)).Buffer;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return null;
        }
    }
}
