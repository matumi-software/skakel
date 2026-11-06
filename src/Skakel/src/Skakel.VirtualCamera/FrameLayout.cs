namespace Skakel.VirtualCamera;

/// <summary>
/// The shared frame memory's layout, version 1: a 4096 byte header, three frame slots and an idle
/// slot. <c>docs/virtual-camera.md</c> is the contract; <c>skakel-vcam</c>'s <c>layout.rs</c> is the
/// Rust side of it.
/// </summary>
internal static class FrameLayout
{
    public const uint Magic = 0x43564B53; // "SKVC"
    public const uint Version = 1;
    public const int HeaderSize = 4096;
    public const int SlotCount = 3;
    public const int SlotAlign = 64;
    public const uint FourccNv12 = 0x3231564E; // "NV12"
    public const ulong Writing = ulong.MaxValue;
    public const uint DefaultIdleTimeoutMs = 2000;
    public const uint MinIdleTimeoutMs = 100;
    public const uint MaxIdleTimeoutMs = 60_000;
    public const int MinDimension = 16;
    public const int MaxDimension = 4096;
    public const int MaxFps = 120;

    public const int MagicOffset = 0;
    public const int VersionOffset = 4;
    public const int HeaderSizeOffset = 8;
    public const int WidthOffset = 12;
    public const int HeightOffset = 16;
    public const int FpsNumOffset = 20;
    public const int FpsDenOffset = 24;
    public const int FourccOffset = 28;
    public const int FrameSizeOffset = 32;
    public const int SlotCountOffset = 36;
    public const int SlotSizeOffset = 40;
    public const int TotalSizeOffset = 48;
    public const int ProducerStateOffset = 64;
    public const int ProducerPidOffset = 68;
    public const int IdleTimeoutOffset = 72;
    public const int FrameSeqOffset = 80;
    public const int IdleSeqOffset = 88;
    public const int SlotSeqOffset = 96;
}

/// <summary>The size and rate of one camera's frames.</summary>
internal readonly record struct FrameFormat(int Width, int Height, int FpsNum, int FpsDen)
{
    /// <summary>Null unless width and height are even and 16 to 4096, and the rate is 1 to 120 a second.</summary>
    public static FrameFormat? Create(int width, int height, int fpsNum, int fpsDen)
    {
        static bool DimensionOk(int d) => d is >= FrameLayout.MinDimension and <= FrameLayout.MaxDimension && d % 2 == 0;
        if (!DimensionOk(width) || !DimensionOk(height) || fpsNum <= 0 || fpsDen <= 0 || fpsNum < fpsDen || (long)fpsNum > (long)FrameLayout.MaxFps * fpsDen)
        {
            return null;
        }

        return new FrameFormat(width, height, fpsNum, fpsDen);
    }

    /// <summary>Bytes in one NV12 frame.</summary>
    public int FrameSize => Width * Height * 3 / 2;

    /// <summary>Bytes from one slot to the next.</summary>
    public int SlotSize => (FrameSize + FrameLayout.SlotAlign - 1) / FrameLayout.SlotAlign * FrameLayout.SlotAlign;

    /// <summary>Bytes in the whole shared memory.</summary>
    public long TotalSize => FrameLayout.HeaderSize + ((long)FrameLayout.SlotCount + 1) * SlotSize;
}
