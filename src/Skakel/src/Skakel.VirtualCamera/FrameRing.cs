namespace Skakel.VirtualCamera;

/// <summary>Why a header cannot be used.</summary>
internal enum HeaderStatus
{
    Ok,
    /// <summary>The magic is not there yet: the media source is still writing the header.</summary>
    NotReady,
    BadMagic,
    UnsupportedVersion,
    Inconsistent,
}

/// <summary>
/// A block of memory holding a camera's header and slots: a mapped view of the shared memory, or
/// native memory in tests. Every shared field is read and written as the contract says: with
/// acquire and release, and each slot guarded by its sequence number.
/// </summary>
internal readonly unsafe struct FrameRegion
{
    private readonly byte* _base;

    public FrameRegion(byte* @base, long length)
    {
        if (@base == null || ((nint)@base & 7) != 0)
        {
            throw new ArgumentException("The region must be aligned to 8 bytes.", nameof(@base));
        }

        _base = @base;
        Length = length;
    }

    public long Length { get; }

    private ref uint U32(int offset) => ref *(uint*)(_base + offset);

    private ref ulong U64(int offset) => ref *(ulong*)(_base + offset);

    public uint ReadU32(int offset) => Volatile.Read(ref U32(offset));

    public void WriteU32(int offset, uint value) => Volatile.Write(ref U32(offset), value);

    public ulong ReadU64(int offset) => Volatile.Read(ref U64(offset));

    public void WriteU64(int offset, ulong value) => Volatile.Write(ref U64(offset), value);

    public Span<byte> Bytes(long offset, int length)
    {
        if (offset < 0 || offset + length > Length)
        {
            throw new ArgumentOutOfRangeException(nameof(offset));
        }

        return new Span<byte>(_base + offset, length);
    }

    /// <summary>Writes a fresh header. Only the media source does this; the producer side has it for tests.</summary>
    public void Initialize(FrameFormat format)
    {
        WriteU32(FrameLayout.VersionOffset, FrameLayout.Version);
        WriteU32(FrameLayout.HeaderSizeOffset, FrameLayout.HeaderSize);
        WriteU32(FrameLayout.WidthOffset, (uint)format.Width);
        WriteU32(FrameLayout.HeightOffset, (uint)format.Height);
        WriteU32(FrameLayout.FpsNumOffset, (uint)format.FpsNum);
        WriteU32(FrameLayout.FpsDenOffset, (uint)format.FpsDen);
        WriteU32(FrameLayout.FourccOffset, FrameLayout.FourccNv12);
        WriteU32(FrameLayout.FrameSizeOffset, (uint)format.FrameSize);
        WriteU32(FrameLayout.SlotCountOffset, FrameLayout.SlotCount);
        WriteU32(FrameLayout.SlotSizeOffset, (uint)format.SlotSize);
        WriteU64(FrameLayout.TotalSizeOffset, (ulong)format.TotalSize);
        WriteU32(FrameLayout.MagicOffset, FrameLayout.Magic);
    }

    /// <summary>The format a version 1 header describes, after checking it fits the region.</summary>
    public HeaderStatus ReadFormat(out FrameFormat format)
    {
        format = default;
        if (Length < FrameLayout.HeaderSize)
        {
            return HeaderStatus.Inconsistent;
        }

        switch (ReadU32(FrameLayout.MagicOffset))
        {
            case 0:
                return HeaderStatus.NotReady;
            case FrameLayout.Magic:
                break;
            default:
                return HeaderStatus.BadMagic;
        }

        if (ReadU32(FrameLayout.VersionOffset) != FrameLayout.Version)
        {
            return HeaderStatus.UnsupportedVersion;
        }

        var read = FrameFormat.Create(
            (int)ReadU32(FrameLayout.WidthOffset),
            (int)ReadU32(FrameLayout.HeightOffset),
            (int)ReadU32(FrameLayout.FpsNumOffset),
            (int)ReadU32(FrameLayout.FpsDenOffset));
        if (read is not { } f)
        {
            return HeaderStatus.Inconsistent;
        }

        var consistent = ReadU32(FrameLayout.HeaderSizeOffset) == FrameLayout.HeaderSize
            && ReadU32(FrameLayout.FourccOffset) == FrameLayout.FourccNv12
            && ReadU32(FrameLayout.FrameSizeOffset) == (uint)f.FrameSize
            && ReadU32(FrameLayout.SlotCountOffset) == FrameLayout.SlotCount
            && ReadU32(FrameLayout.SlotSizeOffset) == (uint)f.SlotSize
            && ReadU64(FrameLayout.TotalSizeOffset) == (ulong)f.TotalSize
            && f.TotalSize <= Length;
        if (!consistent)
        {
            return HeaderStatus.Inconsistent;
        }

        format = f;
        return HeaderStatus.Ok;
    }

    public static long SlotOffset(FrameFormat format, int slot) => FrameLayout.HeaderSize + (long)slot * format.SlotSize;

    public static int SlotSeqOffset(int slot) => FrameLayout.SlotSeqOffset + slot * 8;
}

/// <summary>The producer's side of the ring. It never waits for the reader.</summary>
internal sealed class FrameWriter
{
    private readonly FrameRegion _region;
    private ulong _idleVersion;
    private ulong _pendingSeq;

    private FrameWriter(FrameRegion region, FrameFormat format, ulong idleVersion)
    {
        _region = region;
        Format = format;
        _idleVersion = idleVersion;
    }

    public FrameFormat Format { get; }

    /// <summary>Attaches to an initialised region and marks the producer present.</summary>
    public static HeaderStatus Attach(FrameRegion region, uint pid, uint idleTimeoutMs, out FrameWriter? writer)
    {
        writer = null;
        var status = region.ReadFormat(out var format);
        if (status != HeaderStatus.Ok)
        {
            return status;
        }

        region.WriteU32(FrameLayout.IdleTimeoutOffset, idleTimeoutMs);
        region.WriteU32(FrameLayout.ProducerPidOffset, pid);
        region.WriteU32(FrameLayout.ProducerStateOffset, 1);
        var idle = region.ReadU64(FrameLayout.IdleSeqOffset);
        writer = new FrameWriter(region, format, idle == FrameLayout.Writing ? 0 : idle);
        return HeaderStatus.Ok;
    }

    /// <summary>Marks the next frame's slot as being written and returns it to fill; <see cref="PublishFrame"/> then.</summary>
    public Span<byte> BeginFrame()
    {
        _pendingSeq = _region.ReadU64(FrameLayout.FrameSeqOffset) + 1;
        var slot = (int)(_pendingSeq % FrameLayout.SlotCount);
        _region.WriteU64(FrameRegion.SlotSeqOffset(slot), FrameLayout.Writing);
        Interlocked.MemoryBarrier();
        return _region.Bytes(FrameRegion.SlotOffset(Format, slot), Format.FrameSize);
    }

    /// <summary>Publishes the frame <see cref="BeginFrame"/> handed out. Returns its sequence number.</summary>
    public ulong PublishFrame()
    {
        var seq = _pendingSeq;
        var slot = (int)(seq % FrameLayout.SlotCount);
        _region.WriteU64(FrameRegion.SlotSeqOffset(slot), seq);
        _region.WriteU64(FrameLayout.FrameSeqOffset, seq);
        return seq;
    }

    /// <summary>Marks the idle slot as being written and returns it to fill; <see cref="PublishIdle"/> then.</summary>
    public Span<byte> BeginIdle()
    {
        _idleVersion++;
        _region.WriteU64(FrameLayout.IdleSeqOffset, FrameLayout.Writing);
        Interlocked.MemoryBarrier();
        return _region.Bytes(FrameRegion.SlotOffset(Format, FrameLayout.SlotCount), Format.FrameSize);
    }

    public void PublishIdle() => _region.WriteU64(FrameLayout.IdleSeqOffset, _idleVersion);

    /// <summary>Marks the producer gone, so the camera shows the idle frame at once.</summary>
    public void Detach() => _region.WriteU32(FrameLayout.ProducerStateOffset, 0);
}

/// <summary>The media source's side of the ring, here so the tests can read what the writer wrote.</summary>
internal sealed class FrameReader
{
    private readonly FrameRegion _region;
    private ulong _lastSeq;
    private ulong _lastIdle;

    private FrameReader(FrameRegion region, FrameFormat format)
    {
        _region = region;
        Format = format;
        _lastSeq = region.ReadU64(FrameLayout.FrameSeqOffset);
    }

    public FrameFormat Format { get; }

    public static FrameReader? Open(FrameRegion region) =>
        region.ReadFormat(out var format) == HeaderStatus.Ok ? new FrameReader(region, format) : null;

    public bool ProducerAttached => _region.ReadU32(FrameLayout.ProducerStateOffset) != 0;

    public uint IdleTimeoutMs => _region.ReadU32(FrameLayout.IdleTimeoutOffset) switch
    {
        0 => FrameLayout.DefaultIdleTimeoutMs,
        var t => Math.Clamp(t, FrameLayout.MinIdleTimeoutMs, FrameLayout.MaxIdleTimeoutMs),
    };

    public ulong? ReadNewFrame(Span<byte> destination)
    {
        var seq = _region.ReadU64(FrameLayout.FrameSeqOffset);
        if (seq == 0 || seq == _lastSeq)
        {
            return null;
        }

        var slot = (int)(seq % FrameLayout.SlotCount);
        if (!CopyGuarded(FrameRegion.SlotSeqOffset(slot), seq, FrameRegion.SlotOffset(Format, slot), destination))
        {
            return null;
        }

        _lastSeq = seq;
        return seq;
    }

    public ulong? ReadNewIdle(Span<byte> destination)
    {
        var version = _region.ReadU64(FrameLayout.IdleSeqOffset);
        if (version is 0 or FrameLayout.Writing || version == _lastIdle)
        {
            return null;
        }

        if (!CopyGuarded(FrameLayout.IdleSeqOffset, version, FrameRegion.SlotOffset(Format, FrameLayout.SlotCount), destination))
        {
            return null;
        }

        _lastIdle = version;
        return version;
    }

    private bool CopyGuarded(int seqOffset, ulong expected, long dataOffset, Span<byte> destination)
    {
        if (_region.ReadU64(seqOffset) != expected)
        {
            return false;
        }

        _region.Bytes(dataOffset, Format.FrameSize).CopyTo(destination);
        Interlocked.MemoryBarrier();
        return _region.ReadU64(seqOffset) == expected;
    }
}
