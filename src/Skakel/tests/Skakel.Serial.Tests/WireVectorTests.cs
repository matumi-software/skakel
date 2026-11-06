using Skakel.Protocol.Serial;

namespace Skakel.Serial.Tests;

/// <summary>
/// Pins the bytes the Rust crate <c>skakel-serial</c> pins too, with the same vectors, so the two
/// languages cannot drift apart without one of the suites failing.
/// </summary>
public sealed class WireVectorTests
{
    [Fact]
    public void Serialize_writes_the_client_messages_the_rust_side_pins()
    {
        SerialMessages.Serialize(new SerialSetLineSettings(115200, 8, SerialParity.None, SerialStopBits.OnePointFive, SerialFlowControl.RtsCts))
            .Should().Be("""{"op":"lineSettings","baud":115200,"dataBits":8,"parity":"none","stopBits":"1.5","flowControl":"rtsCts"}""");
        SerialMessages.Serialize(new SerialSetModemLines(null, false)).Should().Be("""{"op":"modemLines","dtr":null,"rts":false}""");
        SerialMessages.Serialize(new SerialBreak(true)).Should().Be("""{"op":"break","on":true}""");
        SerialMessages.Serialize(new SerialPurge(true, false)).Should().Be("""{"op":"purge","input":true,"output":false}""");
    }

    [Fact]
    public void Serialize_writes_the_server_messages_the_rust_side_pins()
    {
        SerialMessages.Serialize(new SerialOpened(new SerialLineSettings(9600, 7, SerialParity.Even, SerialStopBits.Two, SerialFlowControl.XonXoff), new SerialModemStatus(true, false, true, false)))
            .Should().Be("""{"op":"opened","lineSettings":{"baud":9600,"dataBits":7,"parity":"even","stopBits":"2","flowControl":"xonXoff"},"modemStatus":{"cts":true,"dsr":false,"dcd":true,"ri":false}}""");
        SerialMessages.Serialize(new SerialModemStatusChanged(false, true, false, true))
            .Should().Be("""{"op":"modemStatus","cts":false,"dsr":true,"dcd":false,"ri":true}""");
        SerialMessages.Serialize(new SerialError(SerialErrorCode.Unsupported, "1.5 stop bits with 8 data bits"))
            .Should().Be("""{"op":"error","code":"unsupported","detail":"1.5 stop bits with 8 data bits"}""");
        SerialMessages.Serialize(new SerialError(SerialErrorCode.Overrun)).Should().Be("""{"op":"error","code":"overrun","detail":null}""");
        SerialMessages.Serialize(SerialLineSettingsApplied.From(new SerialLineSettings(300, 5, SerialParity.Mark, SerialStopBits.One, SerialFlowControl.None)))
            .Should().Be("""{"op":"lineSettings","baud":300,"dataBits":5,"parity":"mark","stopBits":"1","flowControl":"none"}""");
    }

    [Fact]
    public void TryParseClient_leaves_a_purge_without_flags_at_false()
    {
        SerialMessages.TryParseClient("""{"op":"purge"}""", out var message).Should().BeTrue();

        message.Should().Be(new SerialPurge(false, false));
    }
}
