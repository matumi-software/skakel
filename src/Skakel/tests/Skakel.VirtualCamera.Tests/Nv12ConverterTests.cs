using System.Globalization;

namespace Skakel.VirtualCamera.Tests;

public sealed class Nv12ConverterTests
{
    private static byte[] Rgba(int width, int height, Func<int, int, byte[]> pixel) =>
        [.. Enumerable.Range(0, height).SelectMany(y => Enumerable.Range(0, width).SelectMany(x => pixel(x, y)))];

    private static byte[] Gradient() => Rgba(16, 16, (x, y) => [(byte)(x * 16), (byte)(y * 16), (byte)((x + y) * 8), 255]);

    [Theory]
    [InlineData(0, 0, 0, 16, 128, 128)]
    [InlineData(255, 255, 255, 235, 128, 128)]
    [InlineData(255, 0, 0, 82, 90, 240)]
    [InlineData(0, 255, 0, 144, 54, 34)]
    [InlineData(0, 0, 255, 41, 240, 110)]
    public void Primaries_land_on_the_bt601_values(int r, int g, int b, int y, int u, int v)
    {
        (Nv12Converter.Luma(r, g, b), Nv12Converter.ChromaU(r, g, b), Nv12Converter.ChromaV(r, g, b))
            .Should().Be(((byte)y, (byte)u, (byte)v));
    }

    [Fact]
    public void Convert_gives_the_same_frame_from_rgba_and_bgra()
    {
        var rgba = Gradient();
        var bgra = rgba.Chunk(4).SelectMany(p => new[] { p[2], p[1], p[0], p[3] }).ToArray();
        var a = new byte[384];
        var b = new byte[384];

        Nv12Converter.Convert(rgba, FramePixelFormat.Rgba, 16, 16, a);
        Nv12Converter.Convert(bgra, FramePixelFormat.Bgra, 16, 16, b);

        a.Should().Equal(b);
    }

    [Fact]
    public void Convert_averages_each_two_by_two_block_for_chroma()
    {
        var source = Rgba(4, 2, (x, _) => x switch
        {
            0 => [255, 0, 0, 255],
            1 => [0, 0, 255, 255],
            _ => [255, 255, 255, 255],
        });
        var nv12 = new byte[12];

        Nv12Converter.Convert(source, FramePixelFormat.Rgba, 4, 2, nv12);

        nv12[..8].Should().Equal(82, 41, 235, 235, 82, 41, 235, 235);
        nv12[8..].Should().Equal(Nv12Converter.ChromaU(128, 0, 128), Nv12Converter.ChromaV(128, 0, 128), (byte)128, (byte)128);
    }

    [Fact]
    public void Convert_gives_the_bytes_the_rust_producer_gives()
    {
        // skakel-vcam's convert.rs pins the same hash for the same gradient.
        var nv12 = new byte[384];

        Nv12Converter.Convert(Gradient(), FramePixelFormat.Rgba, 16, 16, nv12);

        CameraContract.Fnv1a64(nv12).ToString("x16", CultureInfo.InvariantCulture).Should().Be("26f90e1faa0a07b9");
    }

    [Fact]
    public void Convert_copies_nv12_as_is()
    {
        var source = Enumerable.Range(0, 384).Select(i => (byte)i).ToArray();
        var nv12 = new byte[384];

        Nv12Converter.Convert(source, FramePixelFormat.Nv12, 16, 16, nv12);

        nv12.Should().Equal(source);
    }

    [Fact]
    public void Convert_refuses_a_frame_of_the_wrong_size()
    {
        var act = () => Nv12Converter.Convert(new byte[10], FramePixelFormat.Rgba, 16, 16, new byte[384]);

        act.Should().Throw<ArgumentException>().WithMessage("*10 bytes*1024*");
    }

    [Fact]
    public void Solid_matches_a_converted_frame()
    {
        var nv12 = new byte[384];

        Nv12Converter.Convert(Rgba(16, 16, (_, _) => [10, 200, 30, 255]), FramePixelFormat.Rgba, 16, 16, nv12);

        Nv12Converter.Solid(16, 16, 10, 200, 30).Should().Equal(nv12);
    }
}
