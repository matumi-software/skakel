namespace Skakel.VirtualCamera;

/// <summary>The pixel layout of a frame handed to the camera.</summary>
public enum FramePixelFormat
{
    /// <summary>NV12: the luma plane, then interleaved U and V at half width and half height.</summary>
    Nv12,

    /// <summary>Four bytes a pixel: red, green, blue, then alpha, which is ignored.</summary>
    Rgba,

    /// <summary>Four bytes a pixel: blue, green, red, then alpha, which is ignored. Windows' usual layout.</summary>
    Bgra,
}

/// <summary>
/// RGBA and BGRA to NV12, BT.601 limited range, the way webcams deliver it. Fixed-point integer
/// arithmetic, so the bytes are the same as the Rust producer's.
/// </summary>
public static class Nv12Converter
{
    /// <summary>Bytes in a tightly packed frame of <paramref name="format"/>.</summary>
    public static int FrameSize(FramePixelFormat format, int width, int height) => format switch
    {
        FramePixelFormat.Nv12 => width * height * 3 / 2,
        FramePixelFormat.Rgba or FramePixelFormat.Bgra => width * height * 4,
        _ => throw new ArgumentOutOfRangeException(nameof(format)),
    };

    /// <summary>
    /// Writes <paramref name="source"/>, a tightly packed frame in <paramref name="format"/>, into
    /// <paramref name="destination"/> as NV12. Width and height are even.
    /// </summary>
    /// <exception cref="ArgumentException">A buffer is not the size the format and dimensions need.</exception>
    public static void Convert(ReadOnlySpan<byte> source, FramePixelFormat format, int width, int height, Span<byte> destination)
    {
        if (width <= 0 || height <= 0 || width % 2 != 0 || height % 2 != 0)
        {
            throw new ArgumentException($"{width}x{height} is not an even size.", nameof(width));
        }

        var expected = FrameSize(format, width, height);
        if (source.Length != expected)
        {
            throw new ArgumentException($"The frame is {source.Length} bytes, {width}x{height} needs {expected}.", nameof(source));
        }

        var nv12 = FrameSize(FramePixelFormat.Nv12, width, height);
        if (destination.Length != nv12)
        {
            throw new ArgumentException($"The destination is {destination.Length} bytes, NV12 at {width}x{height} needs {nv12}.", nameof(destination));
        }

        switch (format)
        {
            case FramePixelFormat.Nv12:
                source.CopyTo(destination);
                break;
            case FramePixelFormat.Rgba:
                FromRgb32(source, width, height, destination, 0, 2);
                break;
            default:
                FromRgb32(source, width, height, destination, 2, 0);
                break;
        }
    }

    internal static byte Luma(int r, int g, int b) => (byte)(((66 * r + 129 * g + 25 * b + 128) >> 8) + 16);

    internal static byte ChromaU(int r, int g, int b) => (byte)(((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128);

    internal static byte ChromaV(int r, int g, int b) => (byte)(((112 * r - 94 * g - 18 * b + 128) >> 8) + 128);

    /// <summary>A solid NV12 frame of one colour.</summary>
    internal static byte[] Solid(int width, int height, byte r, byte g, byte b)
    {
        var lumaLength = width * height;
        var frame = new byte[lumaLength * 3 / 2];
        frame.AsSpan(0, lumaLength).Fill(Luma(r, g, b));
        for (var i = lumaLength; i < frame.Length; i += 2)
        {
            frame[i] = ChromaU(r, g, b);
            frame[i + 1] = ChromaV(r, g, b);
        }

        return frame;
    }

    private static void FromRgb32(ReadOnlySpan<byte> source, int width, int height, Span<byte> destination, int red, int blue)
    {
        var stride = width * 4;
        for (var y = 0; y < height; y++)
        {
            var row = source.Slice(y * stride, stride);
            var luma = destination.Slice(y * width, width);
            for (var x = 0; x < width; x++)
            {
                var px = row.Slice(x * 4, 4);
                luma[x] = Luma(px[red], px[1], px[blue]);
            }
        }

        // Each chroma sample is taken from the average of its 2x2 block.
        var chroma = destination[(width * height)..];
        for (var pair = 0; pair < height / 2; pair++)
        {
            var top = source.Slice(pair * 2 * stride, stride);
            var bottom = source.Slice((pair * 2 + 1) * stride, stride);
            var uv = chroma.Slice(pair * width, width);
            for (var x = 0; x < width / 2; x++)
            {
                var at = x * 8;
                var r = (top[at + red] + top[at + 4 + red] + bottom[at + red] + bottom[at + 4 + red] + 2) >> 2;
                var g = (top[at + 1] + top[at + 5] + bottom[at + 1] + bottom[at + 5] + 2) >> 2;
                var b = (top[at + blue] + top[at + 4 + blue] + bottom[at + blue] + bottom[at + 4 + blue] + 2) >> 2;
                uv[x * 2] = ChromaU(r, g, b);
                uv[x * 2 + 1] = ChromaV(r, g, b);
            }
        }
    }
}
