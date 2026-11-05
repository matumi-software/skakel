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

    private async Task AnswerAsync(Socket socket, CancellationToken cancellationToken)
    {
        var buffer = new byte[2048];
        var anyone = new IPEndPoint(IPAddress.Any, 0);
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var received = await socket.ReceiveFromAsync(buffer, SocketFlags.None, anyone, cancellationToken);
                if (SkakelDiscovery.IsProbe(buffer.AsSpan(0, received.ReceivedBytes)) && Answer() is { } answer && answer.Length <= received.ReceivedBytes)
                {
                    await socket.SendToAsync(answer, SocketFlags.None, received.RemoteEndPoint, cancellationToken);
                }
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
            }
            catch (SocketException ex)
            {
                LogAnswerFailed(ex);
                return;
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
}
