using System.Text.Json.Serialization;

namespace Skakel.Protocol.Serial;

/// <summary>
/// The <c>serial</c> stream type: one serial port on the server, used by one client at a time. Binary
/// frames carry the bytes; text frames carry the control messages in <see cref="SerialMessages"/>.
/// </summary>
public static class SerialStreamType
{
    /// <summary>The stream type.</summary>
    public const string Type = "serial";

    /// <summary>The query string parameter that names the port, by its id in the app's list of ports.</summary>
    public const string PortQuery = "port";

    /// <summary>Close code: the port reported a fault and was closed.</summary>
    public const int PortFault = 4100;
}

/// <summary>Parity.</summary>
public enum SerialParity
{
    /// <summary>No parity bit.</summary>
    None,

    /// <summary>Odd parity.</summary>
    Odd,

    /// <summary>Even parity.</summary>
    Even,

    /// <summary>The parity bit is always 1.</summary>
    Mark,

    /// <summary>The parity bit is always 0.</summary>
    Space,
}

/// <summary>Stop bits, written <c>"1"</c>, <c>"1.5"</c> or <c>"2"</c>.</summary>
public enum SerialStopBits
{
    /// <summary>One stop bit.</summary>
    [JsonStringEnumMemberName("1")]
    One,

    /// <summary>One and a half stop bits.</summary>
    [JsonStringEnumMemberName("1.5")]
    OnePointFive,

    /// <summary>Two stop bits.</summary>
    [JsonStringEnumMemberName("2")]
    Two,
}

/// <summary>Flow control, which the server runs on the real port.</summary>
public enum SerialFlowControl
{
    /// <summary>None.</summary>
    None,

    /// <summary>RTS/CTS. The server drives RTS itself.</summary>
    RtsCts,

    /// <summary>XON/XOFF. The port's driver handles them and they do not appear in the data.</summary>
    XonXoff,
}

/// <summary>Why the port refused a change or reported an error.</summary>
public enum SerialErrorCode
{
    /// <summary>The port cannot take that value.</summary>
    Unsupported,

    /// <summary>A framing error.</summary>
    Framing,

    /// <summary>A parity error.</summary>
    Parity,

    /// <summary>The port's receive buffer overran.</summary>
    Overrun,
}

/// <summary>A port's line settings.</summary>
/// <param name="Baud">Bits per second.</param>
/// <param name="DataBits">5 to 8.</param>
/// <param name="Parity">The parity.</param>
/// <param name="StopBits">The stop bits.</param>
/// <param name="FlowControl">The flow control.</param>
public sealed record SerialLineSettings(int Baud, int DataBits, SerialParity Parity, SerialStopBits StopBits, SerialFlowControl FlowControl);

/// <summary>The state of a port's input lines.</summary>
/// <param name="Cts">Clear to send.</param>
/// <param name="Dsr">Data set ready.</param>
/// <param name="Dcd">Data carrier detect.</param>
/// <param name="Ri">Ring indicator.</param>
public sealed record SerialModemStatus(bool Cts, bool Dsr, bool Dcd, bool Ri);
