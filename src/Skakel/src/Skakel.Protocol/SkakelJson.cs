using System.Text.Json;

namespace Skakel.Protocol;

/// <summary>How Skakel writes and reads JSON: UTF-8, camelCase property names.</summary>
public static class SkakelJson
{
    /// <summary>The options for every JSON body and message Skakel defines.</summary>
    public static JsonSerializerOptions Options { get; } = new(JsonSerializerDefaults.Web);
}
