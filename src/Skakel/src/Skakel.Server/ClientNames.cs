using System.Globalization;
using System.Text;

namespace Skakel.Server;

/// <summary>Client names as they are kept and shown.</summary>
internal static class ClientNames
{
    /// <summary>
    /// The name without Unicode control (Cc) and format (Cf) characters, trimmed. Line breaks and NUL
    /// could forge lines in a log or a UI, and direction overrides and invisible characters could make
    /// one name read as another.
    /// </summary>
    public static string Clean(string? name)
    {
        if (string.IsNullOrEmpty(name))
        {
            return "";
        }

        var kept = new StringBuilder(name.Length);
        foreach (var rune in name.EnumerateRunes())
        {
            if (Rune.GetUnicodeCategory(rune) is not (UnicodeCategory.Control or UnicodeCategory.Format))
            {
                kept.Append(rune.ToString());
            }
        }

        return kept.ToString().Trim();
    }
}
