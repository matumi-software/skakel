using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Skakel.Protocol;

namespace Skakel.Server;

/// <summary>
/// Answers discovery probes on UDP, on the app's port number unless told another. Each answer carries
/// the certificate presented at that moment, so a switch is announced at once. See <see cref="SkakelDiscovery"/>.
/// </summary>
internal sealed partial class SkakelDiscoveryService(
    ServerState state,
    IOptions<SkakelServerOptions> options,
    ILogger<SkakelDiscoveryService> logger) : IHostedService, IDisposable
{
    private readonly SkakelServerOptions _options = options.Value;
    private readonly CancellationTokenSource _stop = new();
    private Socket? _socket;
    private Task? _answering;
    private (string Fingerprint, byte[] Answer)? _answer;

    /// <summary>The UDP port it answers on, once started; null when discovery is off.</summary>
    public int? LocalPort => (_socket?.LocalEndPoint as IPEndPoint)?.Port;

    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (!_options.DiscoveryEnabled)
        {
            return Task.CompletedTask;
        }

        var port = _options.DiscoveryPort ?? _options.Port;
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            socket.Bind(new IPEndPoint(IPAddress.Any, port));
        }
        catch (SocketException ex)
        {
            // Clients can still reach the server by address; the rest of the server runs.
            socket.Dispose();
            LogBindFailed(port, ex);
            return Task.CompletedTask;
        }

        _socket = socket;
        _answering = AnswerAsync(socket, _stop.Token);
        LogAnswering(_options.Name, LocalPort ?? port);
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (_socket is null)
        {
            return;
        }

        await _stop.CancelAsync();
        _socket.Dispose();
        if (_answering is not null)
        {
            await _answering.WaitAsync(cancellationToken).ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
        }

        LogStopped();
    }

    public void Dispose()
    {
        _stop.Dispose();
        _socket?.Dispose();
    }

    /// <summary>The answer for the certificate presented now, built again only when it changed.</summary>
    private byte[] Answer()
    {
        var fingerprint = state.Fingerprint;
        if (_answer is { } cached && cached.Fingerprint == fingerprint)
        {
            return cached.Answer;
        }

        var answer = SkakelDiscovery.CreateAnswer(new DiscoveryAnswer(_options.Name, _options.Port, fingerprint, _options.App, SkakelProtocol.Versions));
        _answer = (fingerprint, answer);
        return answer;
    }

    /// <summary>
    /// Whether a probe can be answered at all: it came from a port, and from one host. Port 0 and the
    /// unspecified, broadcast and multicast addresses are not places an answer can go; on some systems
    /// sending to them fails outright.
    /// </summary>
    internal static bool CanAnswer(IPEndPoint from)
    {
        if (from.Port == 0)
        {
            return false;
        }

        var address = from.Address.IsIPv4MappedToIPv6 ? from.Address.MapToIPv4() : from.Address;
        return address.AddressFamily switch
        {
            // 0.0.0.0/8 is "this network", 224.0.0.0/4 multicast, and everything from 240.0.0.0 up reserved or broadcast.
            AddressFamily.InterNetwork => address.GetAddressBytes()[0] is > 0 and < 224,
            AddressFamily.InterNetworkV6 => !address.Equals(IPAddress.IPv6Any) && !address.IsIPv6Multicast,
            _ => false,
        };
    }

    private async Task AnswerAsync(Socket socket, CancellationToken cancellationToken)
    {
        var buffer = new byte[2048];
        var anyone = new IPEndPoint(IPAddress.Any, 0);
        while (!cancellationToken.IsCancellationRequested)
        {
            SocketReceiveFromResult received;
            try
            {
                received = await socket.ReceiveFromAsync(buffer, SocketFlags.None, anyone, cancellationToken);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException)
            {
                return;
            }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.NetworkReset or SocketError.MessageSize)
            {
                // Windows reports these on the next receive, each about one datagram: an earlier answer that could
                // not be delivered or ran out of hops, or a datagram larger than the buffer, which it drops. Anyone
                // on the network can send the last one, so none of them may stop the answers.
                continue;
            }
            catch (SocketException ex)
            {
                LogAnswerFailed(ex);
                return;
            }

            if (!SkakelDiscovery.IsProbe(buffer.AsSpan(0, received.ReceivedBytes)) || received.RemoteEndPoint is not IPEndPoint from)
            {
                continue;
            }

            if (!CanAnswer(from))
            {
                LogProbeIgnored(from);
                continue;
            }

            var answer = Answer();
            if (answer.Length > received.ReceivedBytes)
            {
                continue;
            }

            try
            {
                await socket.SendToAsync(answer, SocketFlags.None, from, cancellationToken);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException)
            {
                return;
            }
            catch (Exception ex)
            {
                // A failed send is about this one answer, whoever the probe came from. The next probe still gets one.
                LogAnswerNotSent(from, ex);
            }
        }
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Answering discovery on the local network as {Name} (UDP port {Port})")]
    private partial void LogAnswering(string name, int port);

    [LoggerMessage(Level = LogLevel.Error, Message = "Cannot answer discovery: UDP port {Port} is not free. Clients have to enter this server's address")]
    private partial void LogBindFailed(int port, Exception exception);

    [LoggerMessage(Level = LogLevel.Information, Message = "Stopped answering discovery on the local network")]
    private partial void LogStopped();

    [LoggerMessage(Level = LogLevel.Warning, Message = "Stopped answering discovery after a network error")]
    private partial void LogAnswerFailed(Exception exception);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Ignored a discovery probe from {From}, which cannot be answered")]
    private partial void LogProbeIgnored(IPEndPoint from);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Could not answer a discovery probe from {From}")]
    private partial void LogAnswerNotSent(IPEndPoint from, Exception exception);
}
