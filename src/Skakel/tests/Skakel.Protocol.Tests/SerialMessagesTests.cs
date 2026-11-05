using System.Text.Json;
using Skakel.Protocol.Serial;

namespace Skakel.Protocol.Tests;

public sealed class SerialMessagesTests
{
    [Fact]
    public void Serialize_writes_the_op_and_the_wire_names()
    {
        var json = JsonDocument.Parse(SerialMessages.Serialize(new SerialSetLineSettings(115200, 8, SerialParity.None, SerialStopBits.OnePointFive, SerialFlowControl.RtsCts))).RootElement;

        json.GetProperty("op").GetString().Should().Be("lineSettings");
        json.GetProperty("baud").GetInt32().Should().Be(115200);
        json.GetProperty("dataBits").GetInt32().Should().Be(8);
        json.GetProperty("parity").GetString().Should().Be("none");
        json.GetProperty("stopBits").GetString().Should().Be("1.5");
        json.GetProperty("flowControl").GetString().Should().Be("rtsCts");
    }

    [Fact]
    public void Serialize_nests_the_settings_and_status_in_opened()
    {
        var opened = new SerialOpened(new SerialLineSettings(9600, 7, SerialParity.Even, SerialStopBits.Two, SerialFlowControl.XonXoff), new SerialModemStatus(true, false, true, false));

        var json = JsonDocument.Parse(SerialMessages.Serialize(opened)).RootElement;

        json.GetProperty("op").GetString().Should().Be("opened");
        json.GetProperty("lineSettings").GetProperty("flowControl").GetString().Should().Be("xonXoff");
        json.GetProperty("lineSettings").GetProperty("stopBits").GetString().Should().Be("2");
        json.GetProperty("modemStatus").GetProperty("dcd").GetBoolean().Should().BeTrue();
        SerialMessages.TryParseServer(json.GetRawText(), out var parsed).Should().BeTrue();
        parsed.Should().Be(opened);
    }

    [Theory]
    [InlineData("""{"op":"lineSettings","baud":9600,"dataBits":8,"parity":"odd","stopBits":"1","flowControl":"none"}""", typeof(SerialSetLineSettings))]
    [InlineData("""{"baud":9600,"dataBits":8,"parity":"odd","stopBits":"1","flowControl":"none","op":"lineSettings"}""", typeof(SerialSetLineSettings))]
    [InlineData("""{"op":"modemLines","dtr":true}""", typeof(SerialSetModemLines))]
    [InlineData("""{"op":"break","on":true}""", typeof(SerialBreak))]
    [InlineData("""{"op":"purge","input":true,"output":false}""", typeof(SerialPurge))]
    public void TryParseClient_reads_each_client_message(string json, Type expected)
    {
        SerialMessages.TryParseClient(json, out var message).Should().BeTrue();

        message.Should().BeOfType(expected);
    }

    [Fact]
    public void TryParseClient_leaves_a_modem_line_that_was_left_out_null()
    {
        SerialMessages.TryParseClient("""{"op":"modemLines","rts":false}""", out var message).Should().BeTrue();

        message.Should().Be(new SerialSetModemLines(Dtr: null, Rts: false));
    }

    [Theory]
    [InlineData("""{"op":"lineSettings","baud":9600,"dataBits":8,"parity":"odd","stopBits":"1"}""")]
    [InlineData("""{"op":"lineSettings","baud":9600,"dataBits":9,"parity":"odd","stopBits":"1","flowControl":"none"}""")]
    [InlineData("""{"op":"lineSettings","baud":0,"dataBits":8,"parity":"odd","stopBits":"1","flowControl":"none"}""")]
    [InlineData("""{"op":"lineSettings","baud":9600,"dataBits":8,"parity":"odd","stopBits":"3","flowControl":"none"}""")]
    [InlineData("""{"op":"lineSettings","baud":9600,"dataBits":8,"parity":1,"stopBits":"1","flowControl":"none"}""")]
    [InlineData("""{"op":"break"}""")]
    [InlineData("""{"op":"opened"}""")]
    [InlineData("""{"op":"reboot"}""")]
    [InlineData("""{"on":true}""")]
    [InlineData("not json")]
    public void TryParseClient_refuses_anything_else(string json)
    {
        SerialMessages.TryParseClient(json, out var message).Should().BeFalse();

        message.Should().BeNull();
    }

    [Fact]
    public void TryParseServer_reads_an_error_and_applied_settings()
    {
        SerialMessages.TryParseServer("""{"op":"error","code":"unsupported","detail":"1.5 stop bits with 8 data bits"}""", out var error).Should().BeTrue();
        SerialMessages.TryParseServer(SerialMessages.Serialize(SerialLineSettingsApplied.From(new SerialLineSettings(300, 5, SerialParity.Mark, SerialStopBits.One, SerialFlowControl.None))), out var applied).Should().BeTrue();

        error.Should().Be(new SerialError(SerialErrorCode.Unsupported, "1.5 stop bits with 8 data bits"));
        applied.Should().BeOfType<SerialLineSettingsApplied>().Which.Parity.Should().Be(SerialParity.Mark);
    }
}
