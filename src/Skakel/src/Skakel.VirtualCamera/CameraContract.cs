using System.Buffers.Binary;
using System.Globalization;
using System.Text;

namespace Skakel.VirtualCamera;

/// <summary>
/// The names and identifiers both producers and the media source agree on. <c>docs/virtual-camera.md</c>
/// is the contract; <c>skakel-vcam</c>'s <c>contract.rs</c> is the Rust side of it.
/// </summary>
internal static class CameraContract
{
    /// <summary>The media source's CLSID, the same in every version.</summary>
    public const string SourceClsid = "{8138410C-B0A8-4CBC-9E0E-5920362ED550}";

    /// <summary>String: the camera id.</summary>
    public static readonly Guid CameraIdAttribute = new("2823b277-8caa-4866-b746-68f84ca14f41");

    /// <summary>UINT32: width in pixels.</summary>
    public static readonly Guid WidthAttribute = new("cf28fa9f-2299-4faa-8cb9-a39776b685de");

    /// <summary>UINT32: height in pixels.</summary>
    public static readonly Guid HeightAttribute = new("b32ef9c4-4e8f-4d60-8df9-d6e8ecee1900");

    /// <summary>UINT64: frame rate, numerator high, denominator low.</summary>
    public static readonly Guid FrameRateAttribute = new("6818edaf-afd8-4a30-8852-945669ae9cb0");

    /// <summary>String: the SID of the user whose producer may write the shared memory.</summary>
    public static readonly Guid ProducerSidAttribute = new("0a7bd1e8-c693-4bff-8f51-4d15b4b7606a");

    /// <summary>UINT32: the layout version the producer speaks.</summary>
    public static readonly Guid LayoutVersionAttribute = new("52a2c5ab-38fe-4d3e-aa11-8045bb97aaf7");

    public const uint IdleFileMagic = 0x49564B53; // "SKVI"
    public const int IdleFileHeader = 16;

    /// <summary>FNV-1a 64 of <c>&lt;SID&gt;\n&lt;friendly name&gt;</c> in UTF-8, as 16 lowercase hex digits.</summary>
    public static string CameraId(string userSid, string friendlyName) =>
        Fnv1a64(Encoding.UTF8.GetBytes($"{userSid}\n{friendlyName}")).ToString("x16", CultureInfo.InvariantCulture);

    public static string SectionName(string cameraId) => $@"Global\Skakel.VirtualCamera.{cameraId}";

    public static string IdleFilePath(string programData, string cameraId) =>
        Path.Combine(programData, "Skakel", "VirtualCamera", $"{cameraId}.idle");

    /// <summary>Magic, version 1, width and height as little-endian u32, then the NV12 frame.</summary>
    public static byte[] EncodeIdleFile(int width, int height, ReadOnlySpan<byte> nv12)
    {
        var file = new byte[IdleFileHeader + nv12.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(file, IdleFileMagic);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(8), (uint)width);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(12), (uint)height);
        nv12.CopyTo(file.AsSpan(IdleFileHeader));
        return file;
    }

    public static ulong Fnv1a64(ReadOnlySpan<byte> bytes)
    {
        var hash = 0xcbf29ce484222325UL;
        foreach (var b in bytes)
        {
            hash = unchecked((hash ^ b) * 0x100000001b3UL);
        }

        return hash;
    }
}
