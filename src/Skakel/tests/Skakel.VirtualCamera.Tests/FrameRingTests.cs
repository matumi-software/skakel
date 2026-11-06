using System.Globalization;
using System.Runtime.InteropServices;

namespace Skakel.VirtualCamera.Tests;

public sealed unsafe class FrameRingTests
{
    /// <summary>Zeroed native memory aligned like a mapping, freed with the test.</summary>
    private sealed class Memory : IDisposable
    {
        public Memory(long length)
        {
            Length = length;
            Pointer = (byte*)NativeMemory.AlignedAlloc((nuint)length, 4096);
            NativeMemory.Clear(Pointer, (nuint)length);
        }

        public byte* Pointer { get; }

        public long Length { get; }

        public FrameRegion Region => new(Pointer, Length);

        public byte[] ToArray() => new ReadOnlySpan<byte>(Pointer, (int)Length).ToArray();

        public void Dispose() => NativeMemory.AlignedFree(Pointer);
    }

    private static FrameFormat Format(int width, int height) => FrameFormat.Create(width, height, 30, 1)!.Value;

    private static Memory Initialized(FrameFormat format)
    {
        var memory = new Memory(format.TotalSize);
        memory.Region.Initialize(format);
        return memory;
    }

    private static FrameWriter Attach(FrameRegion region, uint pid = 7, uint timeout = 0)
    {
        FrameWriter.Attach(region, pid, timeout, out var writer).Should().Be(HeaderStatus.Ok);
        return writer!;
    }

    private static void Write(FrameWriter writer, Func<int, byte> value)
    {
        var slot = writer.BeginFrame();
        for (var i = 0; i < slot.Length; i++)
        {
            slot[i] = value(i);
        }

        writer.PublishFrame();
    }

    private static void WriteIdle(FrameWriter writer, Func<int, byte> value)
    {
        var slot = writer.BeginIdle();
        for (var i = 0; i < slot.Length; i++)
        {
            slot[i] = value(i);
        }

        writer.PublishIdle();
    }

    /// <summary>
    /// The ring skakel-vcam's layout.rs scripts too: a 16x16 camera, producer 4242 with a 1500 ms
    /// timeout, frames 1 to 4 where byte i of frame k is k * 31 + i * 7, and an idle frame where byte
    /// i is i * 3.
    /// </summary>
    private static byte[] ScriptedRing()
    {
        var format = Format(16, 16);
        using var memory = Initialized(format);
        var writer = Attach(memory.Region, 4242, 1500);
        for (var k = 1; k <= 4; k++)
        {
            Write(writer, i => (byte)(k * 31 + i * 7));
        }

        WriteIdle(writer, i => (byte)(i * 3));
        return memory.ToArray();
    }

    [Fact]
    public void FrameFormat_sizes_follow_the_contract()
    {
        var format = Format(1280, 720);

        format.FrameSize.Should().Be(1_382_400);
        format.SlotSize.Should().Be(1_382_400);
        format.TotalSize.Should().Be(4096 + 4 * 1_382_400);
        Format(18, 18).SlotSize.Should().Be(512);
    }

    [Theory]
    [InlineData(15, 16, 30, 1)]
    [InlineData(17, 16, 30, 1)]
    [InlineData(4098, 16, 30, 1)]
    [InlineData(16, 16, 0, 1)]
    [InlineData(16, 16, 121, 1)]
    [InlineData(16, 16, 1, 2)]
    public void FrameFormat_refuses_what_the_contract_does(int width, int height, int fpsNum, int fpsDen)
    {
        FrameFormat.Create(width, height, fpsNum, fpsDen).Should().BeNull();
    }

    [Fact]
    public void Writer_writes_the_bytes_the_rust_writer_writes()
    {
        // skakel-vcam's layout.rs pins the same hash for the same script, so a ring either side writes
        // is byte for byte the ring the other writes.
        var bytes = ScriptedRing();

        bytes.Length.Should().Be(4096 + 4 * 384);
        bytes[..4].Should().Equal("SKVC"u8.ToArray());
        CameraContract.Fnv1a64(bytes).ToString("x16", CultureInfo.InvariantCulture).Should().Be("2600a0f3fa9b098c");
    }

    [Fact]
    public void Reader_reads_a_scripted_ring_written_elsewhere()
    {
        var format = Format(16, 16);
        using var memory = Initialized(format);
        var reader = FrameReader.Open(memory.Region)!;
        // The bytes arrive as they would from another process, the Rust producer's included.
        ScriptedRing().CopyTo(new Span<byte>(memory.Pointer, (int)memory.Length));
        var frame = new byte[format.FrameSize];

        reader.ProducerAttached.Should().BeTrue();
        reader.IdleTimeoutMs.Should().Be(1500);
        reader.ReadNewFrame(frame).Should().Be(4UL);
        frame.Where((b, i) => b != (byte)(4 * 31 + i * 7)).Should().BeEmpty();
        reader.ReadNewIdle(frame).Should().Be(1UL);
        frame.Where((b, i) => b != (byte)(i * 3)).Should().BeEmpty();
    }

    [Fact]
    public void ReadFormat_is_not_ready_before_the_magic()
    {
        using var memory = new Memory(8192);

        memory.Region.ReadFormat(out _).Should().Be(HeaderStatus.NotReady);
    }

    [Fact]
    public void ReadFormat_refuses_another_version()
    {
        using var memory = Initialized(Format(32, 16));
        memory.Region.WriteU32(FrameLayout.VersionOffset, 2);

        memory.Region.ReadFormat(out _).Should().Be(HeaderStatus.UnsupportedVersion);
    }

    [Fact]
    public void ReadNewFrame_gives_each_new_frame_once()
    {
        var format = Format(16, 16);
        using var memory = Initialized(format);
        var writer = Attach(memory.Region);
        var reader = FrameReader.Open(memory.Region)!;
        var frame = new byte[format.FrameSize];

        reader.ReadNewFrame(frame).Should().BeNull();
        Write(writer, _ => 1);
        reader.ReadNewFrame(frame).Should().Be(1UL);
        reader.ReadNewFrame(frame).Should().BeNull();
        for (byte v = 2; v <= 5; v++)
        {
            var value = v;
            Write(writer, _ => value);
        }

        reader.ReadNewFrame(frame).Should().Be(5UL);
        frame.Should().OnlyContain(b => b == 5);
    }

    [Fact]
    public void ReadNewFrame_drops_a_frame_being_written()
    {
        var format = Format(16, 16);
        using var memory = Initialized(format);
        var writer = Attach(memory.Region);
        var reader = FrameReader.Open(memory.Region)!;
        Write(writer, _ => 1);
        memory.Region.WriteU64(FrameRegion.SlotSeqOffset(1), FrameLayout.Writing);

        reader.ReadNewFrame(new byte[format.FrameSize]).Should().BeNull();
    }

    [Fact]
    public void Detach_marks_the_producer_gone_and_a_new_one_counts_on()
    {
        var format = Format(16, 16);
        using var memory = Initialized(format);
        var first = Attach(memory.Region);
        Write(first, _ => 1);
        first.Detach();
        var reader = FrameReader.Open(memory.Region)!;

        reader.ProducerAttached.Should().BeFalse();
        var second = Attach(memory.Region, 8, 500);
        reader.ProducerAttached.Should().BeTrue();
        reader.IdleTimeoutMs.Should().Be(500);
        second.BeginFrame();
        second.PublishFrame().Should().Be(2UL);
    }
}
