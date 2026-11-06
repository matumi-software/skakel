using System.IO.MemoryMappedFiles;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace Skakel.VirtualCamera;

/// <summary>A camera call failed. The message says which and, for the known causes, why.</summary>
public sealed class VirtualCameraException : Exception
{
    /// <summary>Creates the exception.</summary>
    public VirtualCameraException()
    {
    }

    /// <summary>Creates the exception with a message.</summary>
    public VirtualCameraException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a message and its cause.</summary>
    public VirtualCameraException(string message, Exception? innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>What a camera is: its name, size and rate.</summary>
/// <param name="FriendlyName">The name apps list, 1 to 128 characters. Windows adds "Windows Virtual Camera" to it in some places.</param>
/// <param name="Width">Even, 16 to 4096.</param>
/// <param name="Height">Even, 16 to 4096.</param>
/// <param name="FramesPerSecond">1 to 120.</param>
public sealed record SkakelVirtualCameraOptions(string FriendlyName, int Width, int Height, int FramesPerSecond)
{
    /// <summary>How long the camera repeats the last frame before it shows the idle frame, 100 ms to 60 s.</summary>
    public TimeSpan IdleTimeout { get; init; } = TimeSpan.FromMilliseconds(FrameLayout.DefaultIdleTimeoutMs);
}

/// <summary>
/// A Windows virtual camera this app feeds. Teams, Zoom, browsers and the Camera app list it by name.
/// Creating it registers the camera with Windows for the current user, where it stays, also across
/// restarts, until it is removed; while no app writes to it, it shows the idle frame.
/// </summary>
/// <remarks>
/// <para>Needs Windows 11 (build 22000) and the media source installed once per machine
/// (<c>skakel-vcam-install</c>, elevated). See <c>docs/virtual-camera.md</c>.</para>
/// <para>Frames reach the camera only while some app has it open; before that,
/// <see cref="PushFrame"/> returns false and the frame is dropped.</para>
/// <para>Not thread safe: push frames from one thread at a time.</para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed unsafe class SkakelVirtualCamera : IDisposable
{
    private static readonly TimeSpan RetryInterval = TimeSpan.FromMilliseconds(250);

    private readonly FrameFormat _format;
    private Link? _link;
    private long _nextAttempt;
    private byte[]? _idle;
    private bool _disposed;

    private SkakelVirtualCamera(SkakelVirtualCameraOptions options, FrameFormat format, string id)
    {
        Options = options;
        _format = format;
        Id = id;
    }

    /// <summary>True on Windows 11, where the virtual camera exists.</summary>
    public static bool IsSupported => OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000);

    /// <summary>What the camera was created with.</summary>
    public SkakelVirtualCameraOptions Options { get; }

    /// <summary>The camera's id, which names its shared memory and idle file.</summary>
    public string Id { get; }

    /// <summary>
    /// Creates the camera, or opens it when this user has one of this name already. Needs no elevation,
    /// but the media source must be installed.
    /// </summary>
    /// <exception cref="ArgumentException">The name, size or rate is out of range.</exception>
    /// <exception cref="PlatformNotSupportedException">Windows before 11: the camera cannot exist here.</exception>
    /// <exception cref="VirtualCameraException">Windows refused; the message says why when it is known.</exception>
    public static SkakelVirtualCamera Create(SkakelVirtualCameraOptions options)
    {
        var format = Validate(options);
        EnsureSupported();
        var sid = WindowsIdentity.GetCurrent().User?.Value ?? throw new VirtualCameraException("The current user has no SID.");
        var id = CameraContract.CameraId(sid, options.FriendlyName);
        using (new MediaFoundation.Session())
        using (var camera = MediaFoundation.Camera.Open(options.FriendlyName))
        {
            camera.SetString(CameraContract.CameraIdAttribute, id);
            camera.SetString(CameraContract.ProducerSidAttribute, sid);
            camera.SetUInt32(CameraContract.WidthAttribute, (uint)format.Width);
            camera.SetUInt32(CameraContract.HeightAttribute, (uint)format.Height);
            camera.SetUInt64(CameraContract.FrameRateAttribute, ((ulong)format.FpsNum << 32) | (uint)format.FpsDen);
            camera.SetUInt32(CameraContract.LayoutVersionAttribute, FrameLayout.Version);
            camera.Start();
        }

        return new SkakelVirtualCamera(options, format, id);
    }

    /// <summary>Removes this user's camera of this name from Windows. Apps that have it open lose it.</summary>
    /// <exception cref="PlatformNotSupportedException">Windows before 11.</exception>
    /// <exception cref="VirtualCameraException">Windows refused.</exception>
    public static void Remove(string friendlyName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(friendlyName);
        EnsureSupported();
        using (new MediaFoundation.Session())
        using (var camera = MediaFoundation.Camera.Open(friendlyName))
        {
            camera.Remove();
        }
    }

    /// <summary>True when an app has the camera open and frames reach it. Looks at most every 250 ms.</summary>
    public bool IsConnected
    {
        get
        {
            Connect();
            return _link is not null;
        }
    }

    /// <summary>
    /// Sends one frame, tightly packed in <paramref name="format"/> at the camera's size. Returns false
    /// when no app has the camera open, and the frame went nowhere.
    /// </summary>
    /// <exception cref="ArgumentException">The frame is not the size the camera and format need.</exception>
    /// <exception cref="InvalidOperationException">The camera exists with another size or rate.</exception>
    public bool PushFrame(ReadOnlySpan<byte> frame, FramePixelFormat format)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        CheckSize(frame, format);
        Connect();
        if (_link is not { } link)
        {
            return false;
        }

        Nv12Converter.Convert(frame, format, _format.Width, _format.Height, link.Writer.BeginFrame());
        link.Writer.PublishFrame();
        return true;
    }

    /// <summary>
    /// Sets the frame the camera shows while no app writes to it, such as "&lt;App&gt; is closed". It is
    /// kept in <c>%ProgramData%\Skakel\VirtualCamera</c>, so the camera shows it after the app has gone.
    /// </summary>
    /// <exception cref="ArgumentException">The frame is not the size the camera and format need.</exception>
    /// <exception cref="IOException">The idle file could not be written; the camera has the frame until it closes.</exception>
    public void SetIdleFrame(ReadOnlySpan<byte> frame, FramePixelFormat format)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        CheckSize(frame, format);
        var nv12 = new byte[_format.FrameSize];
        Nv12Converter.Convert(frame, format, _format.Width, _format.Height, nv12);
        _idle = nv12;
        if (_link is { } link)
        {
            nv12.CopyTo(link.Writer.BeginIdle());
            link.Writer.PublishIdle();
        }

        var path = CameraContract.IdleFilePath(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), Id);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        // Written beside it and moved over, so the media source never reads half a file.
        var partial = path + ".partial";
        File.WriteAllBytes(partial, CameraContract.EncodeIdleFile(_format.Width, _format.Height, nv12));
        File.Move(partial, path, overwrite: true);
    }

    /// <summary>Removes the camera from Windows. Apps that have it open lose it.</summary>
    public void Remove()
    {
        Dispose();
        Remove(Options.FriendlyName);
    }

    /// <summary>Tells the camera the app is gone, so it shows the idle frame at once. The camera stays.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _link?.Writer.Detach();
        _link?.Dispose();
        _link = null;
    }

    private static FrameFormat Validate(SkakelVirtualCameraOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(options.FriendlyName) || options.FriendlyName.Length > 128)
        {
            throw new ArgumentException("The camera's name must be 1 to 128 characters.", nameof(options));
        }

        if (options.IdleTimeout < TimeSpan.FromMilliseconds(FrameLayout.MinIdleTimeoutMs) || options.IdleTimeout > TimeSpan.FromMilliseconds(FrameLayout.MaxIdleTimeoutMs))
        {
            throw new ArgumentException("The idle timeout must be 100 ms to 60 s.", nameof(options));
        }

        return FrameFormat.Create(options.Width, options.Height, options.FramesPerSecond, 1)
            ?? throw new ArgumentException(
                $"{options.Width}x{options.Height} at {options.FramesPerSecond} fps is not a camera format: width and height must be even and 16 to 4096, the rate 1 to 120.",
                nameof(options));
    }

    private static void EnsureSupported()
    {
        if (!IsSupported)
        {
            throw new PlatformNotSupportedException($"The virtual camera needs Windows 11 (build 22000 or later); this is {Environment.OSVersion.Version}.");
        }
    }

    private void CheckSize(ReadOnlySpan<byte> frame, FramePixelFormat format)
    {
        var expected = Nv12Converter.FrameSize(format, _format.Width, _format.Height);
        if (frame.Length != expected)
        {
            throw new ArgumentException($"The frame is {frame.Length} bytes, the camera's size needs {expected}.", nameof(frame));
        }
    }

    private void Connect()
    {
        if (_link is not null || Environment.TickCount64 < _nextAttempt)
        {
            return;
        }

        _nextAttempt = Environment.TickCount64 + (long)RetryInterval.TotalMilliseconds;
        MemoryMappedFile file;
        try
        {
            file = MemoryMappedFile.OpenExisting(CameraContract.SectionName(Id), MemoryMappedFileRights.ReadWrite);
        }
        catch (FileNotFoundException)
        {
            // No app has the camera open, so the media source has not made the memory yet.
            return;
        }

        var link = new Link(file);
        var status = FrameWriter.Attach(link.Region, (uint)Environment.ProcessId, (uint)Options.IdleTimeout.TotalMilliseconds, out var writer);
        if (status == HeaderStatus.NotReady)
        {
            link.Dispose();
            return;
        }

        if (status != HeaderStatus.Ok || writer is null)
        {
            link.Dispose();
            throw new InvalidOperationException($"The camera's shared memory cannot be used: {status}.");
        }

        if (writer.Format != _format)
        {
            writer.Detach();
            link.Dispose();
            throw new InvalidOperationException(
                $"The camera exists as {writer.Format.Width}x{writer.Format.Height} at {writer.Format.FpsNum}/{writer.Format.FpsDen} fps; remove it and create it again.");
        }

        link.Writer = writer;
        if (_idle is not null)
        {
            _idle.CopyTo(writer.BeginIdle());
            writer.PublishIdle();
        }

        _link = link;
    }

    /// <summary>The mapped shared memory and the writer over it.</summary>
    private sealed class Link : IDisposable
    {
        private readonly MemoryMappedFile _file;
        private readonly MemoryMappedViewAccessor _view;
        private bool _acquired;

        public Link(MemoryMappedFile file)
        {
            _file = file;
            _view = file.CreateViewAccessor(0, 0, MemoryMappedFileAccess.ReadWrite);
            byte* pointer = null;
            _view.SafeMemoryMappedViewHandle.AcquirePointer(ref pointer);
            _acquired = true;
            Region = new FrameRegion(pointer + _view.PointerOffset, (long)_view.SafeMemoryMappedViewHandle.ByteLength - _view.PointerOffset);
        }

        public FrameRegion Region { get; }

        public FrameWriter Writer { get; set; } = null!;

        public void Dispose()
        {
            if (_acquired)
            {
                _view.SafeMemoryMappedViewHandle.ReleasePointer();
                _acquired = false;
            }

            _view.Dispose();
            _file.Dispose();
        }
    }
}
