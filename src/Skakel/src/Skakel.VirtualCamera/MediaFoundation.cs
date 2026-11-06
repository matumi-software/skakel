using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Skakel.VirtualCamera;

/// <summary>
/// The Media Foundation calls the producer needs: start up, and <c>MFCreateVirtualCamera</c> with the
/// few <c>IMFVirtualCamera</c> methods it uses, called through the vtable. IMFVirtualCamera derives
/// from IMFAttributes, so after IUnknown's 3 slots come IMFAttributes' 30, then its own; the slot
/// numbers below follow mfvirtualcamera.h.
/// </summary>
[SupportedOSPlatform("windows")]
internal static unsafe partial class MediaFoundation
{
    private const uint MfVersion = 0x0002_0070;
    private const uint MfStartupLite = 1;
    private const int SoftwareCameraSource = 0;
    private const int LifetimeSystem = 1;
    private const int AccessCurrentUser = 0;
    private const int CoinitMultithreaded = 0;

    private const int SlotRelease = 2;
    private const int SlotSetUInt32 = 21;
    private const int SlotSetUInt64 = 22;
    private const int SlotSetString = 25;
    private const int SlotStart = 36;
    private const int SlotRemove = 38;

    public const int ClassNotRegistered = unchecked((int)0x80040154);
    public const int AccessDenied = unchecked((int)0x80070005);

    [LibraryImport("ole32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int CoInitializeEx(nint reserved, int coinit);

    [LibraryImport("ole32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial void CoUninitialize();

    [LibraryImport("mfplat.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int MFStartup(uint version, uint flags);

    [LibraryImport("mfplat.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int MFShutdown();

    [LibraryImport("mfsensorgroup.dll", StringMarshalling = StringMarshalling.Utf16)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int MFCreateVirtualCamera(
        int type, int lifetime, int access, string friendlyName, string sourceId, Guid* categories, uint categoryCount, out nint camera);

    /// <summary>Media Foundation started, with COM on the thread, until disposed.</summary>
    public sealed class Session : IDisposable
    {
        private readonly bool _uninitializeCom;

        public Session()
        {
            // S_OK or S_FALSE are ours to undo; RPC_E_CHANGED_MODE means the thread is STA already, which works too.
            _uninitializeCom = CoInitializeEx(0, CoinitMultithreaded) >= 0;
            var hr = MFStartup(MfVersion, MfStartupLite);
            if (hr < 0)
            {
                if (_uninitializeCom)
                {
                    CoUninitialize();
                }

                Marshal.ThrowExceptionForHR(hr);
            }
        }

        public void Dispose()
        {
            _ = MFShutdown();
            if (_uninitializeCom)
            {
                CoUninitialize();
            }
        }
    }

    /// <summary>An <c>IMFVirtualCamera</c>, released when disposed.</summary>
    public sealed class Camera : IDisposable
    {
        private nint _camera;

        private Camera(nint camera) => _camera = camera;

        /// <summary>Opens this user's camera of this name, created for every session until it is removed.</summary>
        public static Camera Open(string friendlyName)
        {
            var hr = MFCreateVirtualCamera(SoftwareCameraSource, LifetimeSystem, AccessCurrentUser, friendlyName, CameraContract.SourceClsid, null, 0, out var camera);
            Check(hr, "create the camera");
            return new Camera(camera);
        }

        private nint Slot(int index) => (*(nint**)_camera)[index];

        public void SetUInt32(Guid key, uint value) =>
            Check(((delegate* unmanaged<nint, Guid*, uint, int>)Slot(SlotSetUInt32))(_camera, &key, value), "set an attribute");

        public void SetUInt64(Guid key, ulong value) =>
            Check(((delegate* unmanaged<nint, Guid*, ulong, int>)Slot(SlotSetUInt64))(_camera, &key, value), "set an attribute");

        public void SetString(Guid key, string value)
        {
            fixed (char* text = value)
            {
                Check(((delegate* unmanaged<nint, Guid*, char*, int>)Slot(SlotSetString))(_camera, &key, text), "set an attribute");
            }
        }

        /// <summary>Registers and enables the camera. No callback: the call returns when it is done.</summary>
        public void Start() => Check(((delegate* unmanaged<nint, nint, int>)Slot(SlotStart))(_camera, 0), "start the camera");

        public void Remove() => Check(((delegate* unmanaged<nint, int>)Slot(SlotRemove))(_camera), "remove the camera");

        public void Dispose()
        {
            if (_camera != 0)
            {
                _ = ((delegate* unmanaged<nint, uint>)Slot(SlotRelease))(_camera);
                _camera = 0;
            }
        }
    }

    private static void Check(int hr, string action)
    {
        if (hr >= 0)
        {
            return;
        }

        var hint = hr switch
        {
            ClassNotRegistered => " The media source is not installed (run skakel-vcam-install as administrator).",
            AccessDenied => " Camera access may be off in Settings > Privacy & security > Camera.",
            _ => "",
        };
        throw new VirtualCameraException($"Could not {action} (0x{hr:X8}).{hint}", Marshal.GetExceptionForHR(hr));
    }
}
