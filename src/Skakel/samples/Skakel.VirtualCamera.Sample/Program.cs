// Feeds the virtual camera "Skakel Test Pattern (.NET)" with moving colour bars until Enter is
// pressed, then leaves it showing its idle frame.
//
//   dotnet run --project samples/Skakel.VirtualCamera.Sample              feed it
//   dotnet run --project samples/Skakel.VirtualCamera.Sample -- --remove  remove the camera
//
// The media source must be installed first: see docs/virtual-camera.md.

using System.Diagnostics;
using Skakel.VirtualCamera;

const string Name = "Skakel Test Pattern (.NET)";
const int Width = 1280;
const int Height = 720;
const int Fps = 30;

if (!OperatingSystem.IsWindows() || !SkakelVirtualCamera.IsSupported)
{
    Console.WriteLine("The virtual camera needs Windows 11 (build 22000 or later).");
    return;
}

if (args.Contains("--remove"))
{
    SkakelVirtualCamera.Remove(Name);
    Console.WriteLine($"Removed \"{Name}\".");
    return;
}

using var camera = SkakelVirtualCamera.Create(new SkakelVirtualCameraOptions(Name, Width, Height, Fps));
camera.SetIdleFrame(Pattern.Closed(Width, Height), FramePixelFormat.Bgra);
Console.WriteLine($"Camera \"{Name}\" ({camera.Id}), {Width}x{Height} at {Fps} fps. Open it in an app; press Enter to stop.");

using var stop = new CancellationTokenSource();
_ = Task.Run(() =>
{
    Console.ReadLine();
    stop.Cancel();
});

var frame = new byte[Width * Height * 4];
var clock = Stopwatch.StartNew();
var connected = false;
for (long n = 0; !stop.IsCancellationRequested; n++)
{
    Pattern.Draw(frame, Width, Height, n);
    var delivered = camera.PushFrame(frame, FramePixelFormat.Bgra);
    if (delivered != connected)
    {
        connected = delivered;
        Console.WriteLine(connected ? "An app has the camera open." : "Waiting for an app to open the camera.");
    }

    var due = TimeSpan.FromSeconds((n + 1) / (double)Fps) - clock.Elapsed;
    if (due > TimeSpan.Zero)
    {
        Thread.Sleep(due);
    }
}

Console.WriteLine("Stopped; the camera shows its idle frame now. Run with --remove to remove it.");

/// <summary>The same pictures as the Rust sample, in BGRA.</summary>
internal static class Pattern
{
    private static readonly byte[][] Bars =
    [
        [192, 192, 192], [0, 192, 192], [192, 192, 0], [0, 192, 0], [192, 0, 192], [0, 0, 192], [192, 0, 0],
    ];

    private static readonly byte[][] Glyphs =
    [
        [0b01110, 0b10001, 0b10000, 0b10000, 0b10000, 0b10001, 0b01110], // C
        [0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b11111], // L
        [0b01110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110], // O
        [0b01111, 0b10000, 0b10000, 0b01110, 0b00001, 0b00001, 0b11110], // S
        [0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b11111], // E
        [0b11110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b11110], // D
    ];

    /// <summary>Colour bars that scroll, a white square that bounces, and the frame counter in binary along the bottom.</summary>
    public static void Draw(byte[] frame, int width, int height, long n)
    {
        var shift = (int)(n * 4 % width);
        var side = height / 4;
        var span = width - side;
        var travel = (int)(n * 8 % (2 * span));
        var boxX = travel < span ? travel : 2 * span - travel;
        var boxY = (height - side) / 2;
        var bitWidth = width / 32;
        for (var y = 0; y < height; y++)
        {
            for (var x = 0; x < width; x++)
            {
                byte r, g, b;
                if (x >= boxX && x < boxX + side && y >= boxY && y < boxY + side)
                {
                    (r, g, b) = (255, 255, 255);
                }
                else if (y >= height - bitWidth)
                {
                    var bit = 31 - Math.Min(x / bitWidth, 31);
                    var on = ((n >> bit) & 1) == 1;
                    (r, g, b) = on ? ((byte)255, (byte)255, (byte)255) : ((byte)16, (byte)16, (byte)16);
                }
                else
                {
                    var bar = Bars[(x + shift) % width * Bars.Length / width];
                    (r, g, b) = (bar[0], bar[1], bar[2]);
                }

                var at = (y * width + x) * 4;
                frame[at] = b;
                frame[at + 1] = g;
                frame[at + 2] = r;
                frame[at + 3] = 255;
            }
        }
    }

    /// <summary>Dark grey with CLOSED across the middle.</summary>
    public static byte[] Closed(int width, int height)
    {
        var scale = Math.Max(width / 60, 1);
        var textWidth = (Glyphs.Length * 6 - 1) * scale;
        var left = Math.Max(width - textWidth, 0) / 2;
        var top = Math.Max(height - 7 * scale, 0) / 2;
        var frame = new byte[width * height * 4];
        for (var y = 0; y < height; y++)
        {
            for (var x = 0; x < width; x++)
            {
                var lit = false;
                if (x >= left && y >= top)
                {
                    int cx = (x - left) / scale, cy = (y - top) / scale;
                    int glyph = cx / 6, column = cx % 6;
                    lit = glyph < Glyphs.Length && column < 5 && cy < 7 && ((Glyphs[glyph][cy] >> (4 - column)) & 1) == 1;
                }

                var v = lit ? (byte)220 : (byte)48;
                var at = (y * width + x) * 4;
                frame[at] = v;
                frame[at + 1] = v;
                frame[at + 2] = v;
                frame[at + 3] = 255;
            }
        }

        return frame;
    }
}
