using System.Text.Encodings.Web;
using System.Text.Json;

namespace Skakel.Protocol;

/// <summary>How Skakel writes and reads JSON: UTF-8, camelCase property names.</summary>
public static class SkakelJson
{
    /// <summary>The options for every JSON body and message Skakel defines.</summary>
    public static JsonSerializerOptions Options { get; } = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// For the discovery answer, which has to fit in a probe's size: text outside ASCII goes as UTF-8
    /// rather than as six-byte escapes. Never used for anything a browser renders.
    /// </summary>
    internal static JsonSerializerOptions Compact { get; } = new(JsonSerializerDefaults.Web)
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };
}
