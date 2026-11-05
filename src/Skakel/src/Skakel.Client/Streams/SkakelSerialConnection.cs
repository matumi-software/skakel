using System.Buffers;
using System.Net.WebSockets;
using System.Text;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Skakel.Protocol.Serial;

namespace Skakel.Client;

/// <summary>What became of a change to the line settings.</summary>
/// <param name="Applied">True when the server echoed the settings: the change is done. False when the port refused it.</param>
/// <param name="LineSettings">The settings on the port now: the echoed ones, or the ones before a refused change.</param>
/// <param name="Detail">Why the port refused, from the server, for a person.</param>
public sealed record SkakelSerialChange(bool Applied, SerialLineSettings LineSettings, string? Detail);

/// <summary>
/// A <c>serial</c> stream: one serial port on the server. Binary data goes both ways through
/// <see cref="SendAsync"/> and <see cref="ReceiveAsync"/>; the port's settings and lines are changed with
/// the control messages, and what the server says about the port comes back as properties and events.
/// A change to the line settings counts as done only when the server echoes it.
/// </summary>
/// <remarks>
/// One task reads the WebSocket, so control messages are seen while the app is not reading data. Data
/// waits in a small buffer: an app that stops reading stops the reads, and the server slows down the
/// port instead of losing bytes. Read data from one task at a time.
/// </remarks>
public sealed partial class SkakelSerialConnection : IAsyncDisposable
{
    /// <summary>How long the server has to say the port is open after the upgrade.</summary>
    internal static readonly TimeSpan OpenTimeout = TimeSpan.FromSeconds(10);

    /// <summary>How long the server has to answer a change to the line settings, unless set otherwise.</summary>
    internal static readonly TimeSpan DefaultChangeTimeout = TimeSpan.FromSeconds(10);

    /// <summary>The longest control message read; a longer one is dropped.</summary>
    private const int MaxControlBytes = 64 * 1024;

    private readonly SkakelStreamConnection _stream;
    private readonly ILogger _logger;
    private readonly Channel<ReadOnlyMemory<byte>> _data = Channel.CreateBounded<ReadOnlyMemory<byte>>(
        new BoundedChannelOptions(16) { SingleReader = true, SingleWriter = true, FullMode = BoundedChannelFullMode.Wait });
    private readonly SemaphoreSlim _sending = new(1, 1);
    private readonly SemaphoreSlim _changing = new(1, 1);
    private readonly CancellationTokenSource _stop = new();
    private readonly TaskCompletionSource<SkakelStreamClose> _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    // Guards _change and _owed, which the receive loop reads as answers arrive.
    private readonly Lock _answers = new();
    private PendingChange? _change;
    // Changes that stopped waiting after they were sent: the next answers that come in are theirs.
    private int _owed;
    private ReadOnlyMemory<byte> _left;
    private Task _receiving = Task.CompletedTask;
    private SerialLineSettings _lineSettings;
    private SerialModemStatus _modemStatus;
    private int _disposed;

    private SkakelSerialConnection(SkakelStreamConnection stream, SerialOpened opened, ILogger logger)
    {
        _stream = stream;
        _logger = logger;
        _lineSettings = opened.LineSettings;
        _modemStatus = opened.ModemStatus;
    }

    /// <summary>Raised when an input line changed. <see cref="ModemStatus"/> has the new state already.</summary>
    public event Func<SerialModemStatus, Task>? ModemStatusChanged;

    /// <summary>Raised when the port reported an error (framing, parity, overrun), or refused something that was not a line settings change.</summary>
    public event Func<SerialError, Task>? ErrorReported;

    /// <summary>The stream underneath.</summary>
    public SkakelStreamConnection Stream => _stream;

    /// <summary>The port's settings, as the server last said.</summary>
    public SerialLineSettings LineSettings => Volatile.Read(ref _lineSettings);

    /// <summary>The port's input lines, as the server last said.</summary>
    public SerialModemStatus ModemStatus => Volatile.Read(ref _modemStatus);

    /// <summary>Completes when the stream ended, with how: <see cref="SerialStreamType.PortFault"/> (4100) is a port that reported a fault.</summary>
    public Task<SkakelStreamClose> Closed => _closed.Task;

    /// <summary>Sends bytes to the port.</summary>
    /// <param name="data">The bytes.</param>
    /// <param name="cancellationToken">Cancels the send.</param>
    /// <exception cref="SkakelException">The stream has ended (<see cref="SkakelFailureKind.ConnectionLost"/>).</exception>
    public Task SendAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default) =>
        SendFrameAsync(data, WebSocketMessageType.Binary, cancellationToken);

    /// <summary>Reads bytes that came from the port. Returns 0 once the stream has ended and everything was read.</summary>
    /// <param name="buffer">Where to put them.</param>
    /// <param name="cancellationToken">Stops waiting.</param>
    public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty)
        {
            return 0;
        }

        while (_left.IsEmpty)
        {
            if (!await _data.Reader.WaitToReadAsync(cancellationToken))
            {
                return 0;
            }

            _data.Reader.TryRead(out _left);
        }

        var count = Math.Min(buffer.Length, _left.Length);
        _left[..count].CopyTo(buffer);
        _left = _left[count..];
        return count;
    }

    /// <summary>How long the server has to answer a change to the line settings: 10 seconds.</summary>
    internal TimeSpan ChangeTimeout { get; set; } = DefaultChangeTimeout;

    /// <summary>
    /// Changes the port's settings and waits until the server echoes them, or the port refuses. One
    /// change at a time; the server has 10 seconds to answer, so a change it never answers does not hold
    /// up the next. An answer that comes after its change stopped waiting is not taken for the next one.
    /// </summary>
    /// <param name="settings">Every setting; the protocol has no partial change.</param>
    /// <param name="cancellationToken">Stops waiting. The change may still be applied.</param>
    /// <exception cref="SkakelException">The stream ended before the server answered (<see cref="SkakelFailureKind.ConnectionLost"/>), or the server did not answer within 10 seconds (<see cref="SkakelFailureKind.UnexpectedAnswer"/>). Either way the change may still be applied; <see cref="LineSettings"/> follows what the server says.</exception>
    public async Task<SkakelSerialChange> SetLineSettingsAsync(SerialLineSettings settings, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(settings);
        await _changing.WaitAsync(cancellationToken);
        var pending = new PendingChange(settings, new TaskCompletionSource<SerialServerMessage>(TaskCreationOptions.RunContinuationsAsynchronously));
        var sent = false;
        try
        {
            lock (_answers)
            {
                _change = pending;
            }

            if (_closed.Task.IsCompleted)
            {
                throw new SkakelException(SkakelFailureKind.ConnectionLost);
            }

            using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            limit.CancelAfter(ChangeTimeout);
            try
            {
                await SendControlAsync(new SerialSetLineSettings(settings.Baud, settings.DataBits, settings.Parity, settings.StopBits, settings.FlowControl), limit.Token);
                sent = true;
                return await pending.Answer.Task.WaitAsync(limit.Token) switch
                {
                    SerialLineSettingsApplied applied => new SkakelSerialChange(true, ToSettings(applied), null),
                    SerialError refused => new SkakelSerialChange(false, LineSettings, refused.Detail),
                    var other => throw new InvalidOperationException($"Unexpected answer {other.GetType().Name}."),
                };
            }
            catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
            {
                LogChangeUnanswered(_stream.Type, ChangeTimeout.TotalSeconds);
                throw new SkakelException(SkakelFailureKind.UnexpectedAnswer, new TimeoutException("The server did not answer the change to the line settings in time.", ex));
            }
        }
        finally
        {
            lock (_answers)
            {
                _change = null;
                if (sent && !pending.Answer.Task.IsCompleted)
                {
                    _owed++;
                }
            }

            _changing.Release();
        }
    }

    /// <summary>Sets the output lines. A line left null stays as it is. RTS is ignored while flow control is RTS/CTS.</summary>
    /// <param name="dtr">Data terminal ready.</param>
    /// <param name="rts">Request to send.</param>
    /// <param name="cancellationToken">Cancels the send.</param>
    public Task SetModemLinesAsync(bool? dtr = null, bool? rts = null, CancellationToken cancellationToken = default) =>
        SendControlAsync(new SerialSetModemLines(dtr, rts), cancellationToken);

    /// <summary>Starts or ends a break.</summary>
    /// <param name="enabled">True to start it, false to end it.</param>
    /// <param name="cancellationToken">Cancels the send.</param>
    public Task SetBreakAsync(bool enabled, CancellationToken cancellationToken = default) =>
        SendControlAsync(new SerialBreak(enabled), cancellationToken);

    /// <summary>Throws away what is buffered on the server.</summary>
    /// <param name="input">The bytes read from the port and not sent yet.</param>
    /// <param name="output">The bytes waiting to be written to the port.</param>
    /// <param name="cancellationToken">Cancels the send.</param>
    public Task PurgeAsync(bool input = false, bool output = false, CancellationToken cancellationToken = default) =>
        SendControlAsync(new SerialPurge(input, output), cancellationToken);

    /// <summary>Closes the stream normally, waits briefly for the server's answer, and lets go of it.</summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
        {
            return;
        }

        await _stream.CloseAsync();
        await _stop.CancelAsync();
        await _receiving.ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
        _stream.Dispose();
        _stop.Dispose();
        _sending.Dispose();
        _changing.Dispose();
    }

    /// <summary>Waits for the server's <c>opened</c>, then starts reading.</summary>
    internal static async Task<SkakelSerialConnection> StartAsync(SkakelStreamConnection stream, ILogger logger, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(OpenTimeout);
        var buffer = new ArrayBufferWriter<byte>();
        try
        {
            while (true)
            {
                var received = await stream.WebSocket.ReceiveAsync(buffer.GetMemory(4096), timeout.Token);
                if (received.MessageType == WebSocketMessageType.Close)
                {
                    LogClosedBeforeOpen(logger, stream.Close?.Code);
                    throw new SkakelException(SkakelFailureKind.ConnectionLost);
                }

                buffer.Advance(received.Count);
                if (received.MessageType != WebSocketMessageType.Text || buffer.WrittenCount > MaxControlBytes)
                {
                    throw new InvalidDataException("The serial stream did not start with an opened message.");
                }

                if (!received.EndOfMessage)
                {
                    continue;
                }

                if (!SerialMessages.TryParseServer(Encoding.UTF8.GetString(buffer.WrittenSpan), out var message) || message is not SerialOpened opened)
                {
                    throw new InvalidDataException("The serial stream did not start with an opened message.");
                }

                var serial = new SkakelSerialConnection(stream, opened, logger);
                serial._receiving = Task.Run(serial.ReceiveLoopAsync, CancellationToken.None);
                return serial;
            }
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw Failures.Exception(ex);
        }
    }

    private static SerialLineSettings ToSettings(SerialLineSettingsApplied applied) =>
        new(applied.Baud, applied.DataBits, applied.Parity, applied.StopBits, applied.FlowControl);

    private Task SendControlAsync(SerialClientMessage message, CancellationToken cancellationToken) =>
        SendFrameAsync(Encoding.UTF8.GetBytes(SerialMessages.Serialize(message)), WebSocketMessageType.Text, cancellationToken);

    /// <summary>One frame at a time, so a control message lands between the bytes sent before and after it.</summary>
    private async Task SendFrameAsync(ReadOnlyMemory<byte> frame, WebSocketMessageType type, CancellationToken cancellationToken)
    {
        await _sending.WaitAsync(cancellationToken);
        try
        {
            await _stream.WebSocket.SendAsync(frame, type, endOfMessage: true, cancellationToken);
        }
        catch (Exception ex) when (ex is WebSocketException or IOException or ObjectDisposedException)
        {
            throw new SkakelException(SkakelFailureKind.ConnectionLost, ex);
        }
        finally
        {
            _sending.Release();
        }
    }

    private async Task ReceiveLoopAsync()
    {
        var socket = _stream.WebSocket;
        var buffer = new byte[16 * 1024];
        var text = new ArrayBufferWriter<byte>();
        var tooLong = false;
        try
        {
            while (true)
            {
                var received = await socket.ReceiveAsync(buffer.AsMemory(), _stop.Token);
                if (received.MessageType == WebSocketMessageType.Close)
                {
                    await AnswerCloseAsync(socket);
                    return;
                }

                if (received.MessageType == WebSocketMessageType.Binary)
                {
                    if (received.Count > 0)
                    {
                        await _data.Writer.WriteAsync(buffer.AsMemory(0, received.Count).ToArray(), _stop.Token);
                    }

                    continue;
                }

                tooLong |= text.WrittenCount + received.Count > MaxControlBytes;
                if (!tooLong)
                {
                    text.Write(buffer.AsSpan(0, received.Count));
                }

                if (!received.EndOfMessage)
                {
                    continue;
                }

                if (tooLong)
                {
                    LogControlDropped(_stream.Type, "too long");
                }
                else
                {
                    await HandleAsync(Encoding.UTF8.GetString(text.WrittenSpan));
                }

                text.ResetWrittenCount();
                tooLong = false;
            }
        }
        catch (Exception ex) when (ex is WebSocketException or OperationCanceledException or ObjectDisposedException or IOException)
        {
            LogReceiveEnded(_stream.Type, ex.Message);
        }
        finally
        {
            _data.Writer.TryComplete();
            lock (_answers)
            {
                _change?.Answer.TrySetException(new SkakelException(SkakelFailureKind.ConnectionLost));
            }

            _closed.TrySetResult(_stream.Close ?? SkakelStreamClose.From(null, null));
        }
    }

    private async Task HandleAsync(string json)
    {
        if (!SerialMessages.TryParseServer(json, out var message))
        {
            LogControlDropped(_stream.Type, "not a serial message");
            return;
        }

        switch (message)
        {
            case SerialOpened opened:
                Volatile.Write(ref _lineSettings, opened.LineSettings);
                Volatile.Write(ref _modemStatus, opened.ModemStatus);
                break;
            case SerialLineSettingsApplied applied:
                Volatile.Write(ref _lineSettings, ToSettings(applied));
                AnswerFor(applied)?.TrySetResult(applied);
                break;
            case SerialModemStatusChanged changed:
                var status = new SerialModemStatus(changed.Cts, changed.Dsr, changed.Dcd, changed.Ri);
                Volatile.Write(ref _modemStatus, status);
                await ModemStatusChanged.RaiseAsync(status, _logger);
                break;
            case SerialError { Code: SerialErrorCode.Unsupported } refused when AnswerFor(refused) is { } pending:
                pending.TrySetResult(refused);
                break;
            case SerialError error:
                await ErrorReported.RaiseAsync(error, _logger);
                break;
        }
    }

    /// <summary>
    /// The change an answer belongs to, or null. Answers come in the order the changes went out, so one
    /// that arrives while an earlier change is still owed its answer is that change's, and is not taken
    /// for the pending one; only an echo of exactly the pending change's settings is always its own.
    /// </summary>
    private TaskCompletionSource<SerialServerMessage>? AnswerFor(SerialServerMessage answer)
    {
        lock (_answers)
        {
            if (answer is SerialLineSettingsApplied applied && _change is { } exact && ToSettings(applied) == exact.Settings)
            {
                _owed = 0;
                return exact.Answer;
            }

            if (_owed > 0)
            {
                _owed--;
                return null;
            }

            return _change?.Answer;
        }
    }

    /// <summary>Answers the server's close frame, so the close completes on both ends.</summary>
    private static async Task AnswerCloseAsync(WebSocket socket)
    {
        if (socket.State != WebSocketState.CloseReceived)
        {
            return;
        }

        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            await socket.CloseOutputAsync(socket.CloseStatus ?? WebSocketCloseStatus.NormalClosure, null, timeout.Token);
        }
        catch (Exception ex) when (ex is WebSocketException or OperationCanceledException or ObjectDisposedException or IOException)
        {
            // The server has gone; the stream is over either way.
        }
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "A {Type} stream stopped reading: {Reason}")]
    private partial void LogReceiveEnded(string type, string reason);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Dropped a control message on a {Type} stream: {Reason}")]
    private partial void LogControlDropped(string type, string reason);

    [LoggerMessage(Level = LogLevel.Information, Message = "A serial stream closed with {Code} before the port opened")]
    private static partial void LogClosedBeforeOpen(ILogger logger, int? code);

    [LoggerMessage(Level = LogLevel.Warning, Message = "The server did not answer a change to the line settings on a {Type} stream within {Seconds} seconds")]
    private partial void LogChangeUnanswered(string type, double seconds);

    /// <summary>A change waiting for its answer, and the settings it asked for.</summary>
    private sealed record PendingChange(SerialLineSettings Settings, TaskCompletionSource<SerialServerMessage> Answer);
}
