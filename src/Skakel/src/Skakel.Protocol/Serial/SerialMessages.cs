using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Skakel.Protocol.Serial;

/// <summary>A control message from the client to the server, one JSON object per text frame, told apart by <c>op</c>.</summary>
[JsonPolymorphic(TypeDiscriminatorPropertyName = "op", UnknownDerivedTypeHandling = JsonUnknownDerivedTypeHandling.FailSerialization)]
[JsonDerivedType(typeof(SerialSetLineSettings), "lineSettings")]
[JsonDerivedType(typeof(SerialSetModemLines), "modemLines")]
[JsonDerivedType(typeof(SerialBreak), "break")]
[JsonDerivedType(typeof(SerialPurge), "purge")]
public abstract record SerialClientMessage;

/// <summary><c>lineSettings</c>: change the port's settings. Every field is required.</summary>
/// <param name="Baud">Bits per second.</param>
/// <param name="DataBits">5 to 8.</param>
/// <param name="Parity">The parity.</param>
/// <param name="StopBits">The stop bits.</param>
/// <param name="FlowControl">The flow control.</param>
public sealed record SerialSetLineSettings(int Baud, int DataBits, SerialParity Parity, SerialStopBits StopBits, SerialFlowControl FlowControl) : SerialClientMessage
{
    /// <summary>The settings this message asks for.</summary>
    public SerialLineSettings ToSettings() => new(Baud, DataBits, Parity, StopBits, FlowControl);
}

/// <summary><c>modemLines</c>: set the output lines. A line left out stays as it is.</summary>
/// <param name="Dtr">Data terminal ready.</param>
/// <param name="Rts">Request to send. Ignored while flow control is <see cref="SerialFlowControl.RtsCts"/>.</param>
public sealed record SerialSetModemLines(bool? Dtr = null, bool? Rts = null) : SerialClientMessage;

/// <summary><c>break</c>: start or end a break.</summary>
/// <param name="On">True to start it, false to end it.</param>
public sealed record SerialBreak(bool On) : SerialClientMessage;

/// <summary><c>purge</c>: throw away what is buffered on the server.</summary>
/// <param name="Input">The bytes read from the port and not sent yet.</param>
/// <param name="Output">The bytes waiting to be written to the port.</param>
public sealed record SerialPurge(bool Input = false, bool Output = false) : SerialClientMessage;

/// <summary>A control message from the server to the client, told apart by <c>op</c>.</summary>
[JsonPolymorphic(TypeDiscriminatorPropertyName = "op", UnknownDerivedTypeHandling = JsonUnknownDerivedTypeHandling.FailSerialization)]
[JsonDerivedType(typeof(SerialOpened), "opened")]
[JsonDerivedType(typeof(SerialLineSettingsApplied), "lineSettings")]
[JsonDerivedType(typeof(SerialModemStatusChanged), "modemStatus")]
[JsonDerivedType(typeof(SerialError), "error")]
public abstract record SerialServerMessage;

/// <summary><c>opened</c>: the first message after the upgrade, with the port as it is now.</summary>
/// <param name="LineSettings">The port's settings.</param>
/// <param name="ModemStatus">The port's input lines.</param>
public sealed record SerialOpened(SerialLineSettings LineSettings, SerialModemStatus ModemStatus) : SerialServerMessage;

/// <summary><c>lineSettings</c>: the settings now on the port, after a change was applied. A client treats a change as done only when this comes back.</summary>
/// <param name="Baud">Bits per second.</param>
/// <param name="DataBits">5 to 8.</param>
/// <param name="Parity">The parity.</param>
/// <param name="StopBits">The stop bits.</param>
/// <param name="FlowControl">The flow control.</param>
public sealed record SerialLineSettingsApplied(int Baud, int DataBits, SerialParity Parity, SerialStopBits StopBits, SerialFlowControl FlowControl) : SerialServerMessage
{
    /// <summary>The message for these settings.</summary>
    public static SerialLineSettingsApplied From(SerialLineSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return new(settings.Baud, settings.DataBits, settings.Parity, settings.StopBits, settings.FlowControl);
    }
}

/// <summary><c>modemStatus</c>: an input line changed.</summary>
/// <param name="Cts">Clear to send.</param>
/// <param name="Dsr">Data set ready.</param>
/// <param name="Dcd">Data carrier detect.</param>
/// <param name="Ri">Ring indicator.</param>
public sealed record SerialModemStatusChanged(bool Cts, bool Dsr, bool Dcd, bool Ri) : SerialServerMessage;

/// <summary><c>error</c>: a change the port refused, which leaves the settings as they were, or errors the port reported.</summary>
/// <param name="Code">What kind of error.</param>
/// <param name="Detail">What happened, for a person.</param>
public sealed record SerialError(SerialErrorCode Code, string? Detail = null) : SerialServerMessage;

/// <summary>Writes and reads the serial stream's control messages.</summary>
public static class SerialMessages
{
    /// <summary>
    /// The JSON options for the control messages: camelCase, enums as their wire names, <c>op</c>
    /// anywhere in the object, and every field without a default required.
    /// </summary>
    public static JsonSerializerOptions Options { get; } = new(JsonSerializerDefaults.Web)
    {
        AllowOutOfOrderMetadataProperties = true,
        RespectRequiredConstructorParameters = true,
        RespectNullableAnnotations = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase, allowIntegerValues: false) },
    };

    /// <summary>The JSON text of a message from the client.</summary>
    public static string Serialize(SerialClientMessage message) => JsonSerializer.Serialize(message, Options);

    /// <summary>The JSON text of a message from the server.</summary>
    public static string Serialize(SerialServerMessage message) => JsonSerializer.Serialize(message, Options);

    /// <summary>
    /// Reads a message from the client. False for anything that is not one: broken JSON, an unknown
    /// <c>op</c>, a missing field, or data bits outside 5 to 8 or a baud rate that is not positive.
    /// </summary>
    public static bool TryParseClient(string json, [NotNullWhen(true)] out SerialClientMessage? message)
    {
        message = TryParse<SerialClientMessage>(json);
        if (message is SerialSetLineSettings { Baud: < 1 } or SerialSetLineSettings { DataBits: < 5 or > 8 })
        {
            message = null;
        }

        return message is not null;
    }

    /// <summary>Reads a message from the server. False for anything that is not one.</summary>
    public static bool TryParseServer(string json, [NotNullWhen(true)] out SerialServerMessage? message)
    {
        message = TryParse<SerialServerMessage>(json);
        return message is not null;
    }

    private static T? TryParse<T>(string json)
        where T : class
    {
        ArgumentNullException.ThrowIfNull(json);
        try
        {
            return JsonSerializer.Deserialize<T>(json, Options);
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException)
        {
            return null;
        }
    }
}
