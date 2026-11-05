namespace Skakel.Protocol;

/// <summary>The codes a stream's close frame carries.</summary>
public static class SkakelCloseCodes
{
    /// <summary>Closed normally.</summary>
    public const int Normal = 1000;

    /// <summary>The client was revoked.</summary>
    public const int Revoked = 4001;

    /// <summary>The client's secret was rotated.</summary>
    public const int Rotated = 4002;

    /// <summary>The server is stopping, or no longer serves this type.</summary>
    public const int Stopping = 4003;

    /// <summary>The target went away (unplugged, removed).</summary>
    public const int TargetGone = 4004;

    /// <summary>The first code a stream type may define for itself.</summary>
    public const int FirstTypeDefined = 4100;

    /// <summary>The last code a stream type may define for itself.</summary>
    public const int LastTypeDefined = 4999;

    /// <summary>The close code for one of <see cref="SkakelClosingReasons"/>.</summary>
    public static int For(string reason) => reason switch
    {
        SkakelClosingReasons.Revoked => Revoked,
        SkakelClosingReasons.Rotated => Rotated,
        SkakelClosingReasons.Stopping => Stopping,
        _ => throw new ArgumentOutOfRangeException(nameof(reason), reason, "Not a Skakel closing reason."),
    };
}
