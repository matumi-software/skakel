//! The Skakel virtual camera's media source: the COM DLL the Windows Frame Server loads for every
//! camera created with `skakel-vcam`. It reads frames from the shared memory a producer writes and
//! hands them to Frame Server at the camera's rate. See `docs/virtual-camera.md`.
//!
//! The COM objects follow Microsoft's VirtualCamera sample (microsoft/Windows-Camera,
//! Samples/VirtualCamera, MIT, Copyright (c) Microsoft Corporation) and smourier/VCamSample (MIT,
//! Copyright (c) 2024-2026 Simon Mourier). The code is written anew in Rust; where it follows their
//! structure, the comment says so.

#![cfg(windows)]
// The linker would like the Dll* exports marked PRIVATE, which only keeps them out of the import
// library. COM and regsvr32 find them by name either way, and Rust has no way to say PRIVATE.
#![allow(linker_messages)]

mod activate;
mod config;
mod factory;
mod frames;
mod source;
mod stream;

use std::ffi::{c_char, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use windows::Win32::Foundation::{
    CLASS_E_CLASSNOTAVAILABLE, E_FAIL, E_POINTER, HMODULE, S_FALSE, S_OK,
};
use windows::Win32::System::Diagnostics::Debug::OutputDebugStringW;
use windows::Win32::System::LibraryLoader::{
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
    GetModuleFileNameW, GetModuleHandleExW,
};
use windows::core::{GUID, HRESULT, HSTRING, IUnknown, Interface, PCWSTR};

use skakel_vcam::contract::SOURCE_CLSID;

/// COM objects alive, and `LockServer` locks held. The DLL may unload only when both are zero.
static OBJECTS: AtomicUsize = AtomicUsize::new(0);
static LOCKS: AtomicUsize = AtomicUsize::new(0);

/// Counts one live COM object for as long as it lives.
pub(crate) struct ObjectCount;

impl ObjectCount {
    pub(crate) fn new() -> Self {
        OBJECTS.fetch_add(1, Ordering::SeqCst);
        Self
    }
}

impl Drop for ObjectCount {
    fn drop(&mut self) {
        OBJECTS.fetch_sub(1, Ordering::SeqCst);
    }
}

pub(crate) fn lock_server(lock: bool) {
    if lock {
        LOCKS.fetch_add(1, Ordering::SeqCst);
    } else {
        LOCKS.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Writes to the debugger output, which DebugView shows for the Frame Server's processes too.
pub(crate) fn log(message: &str) {
    let text = HSTRING::from(format!("[skakel-vcam {}] {message}\n", std::process::id()));
    unsafe { OutputDebugStringW(&text) };
}

/// Locks `mutex`, and goes on with what is in it when a panic poisoned it. A panic is caught at the
/// COM boundary (see `guard`) and must not make every later call on the object panic too.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "no message".to_owned())
}

/// Runs the body of a COM method or export. A panic must not unwind out of an `extern "system"`
/// function: since Rust 1.81 that aborts the process, and this DLL runs inside the Frame Server,
/// shared with every camera on the machine. It is logged and becomes `E_FAIL` instead.
pub(crate) fn guard<T>(
    what: &str,
    body: impl FnOnce() -> windows::core::Result<T>,
) -> windows::core::Result<T> {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or_else(|payload| {
        log(&format!("{what} panicked: {}", panic_text(&*payload)));
        Err(E_FAIL.into())
    })
}

/// `guard` for an export that returns an `HRESULT`.
fn guard_hresult(what: &str, body: impl FnOnce() -> HRESULT) -> HRESULT {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or_else(|payload| {
        log(&format!("{what} panicked: {}", panic_text(&*payload)));
        E_FAIL
    })
}

/// From olectl.h: registration failed.
const SELFREG_E_CLASS: HRESULT = HRESULT(0x8004_0201_u32 as i32);

/// The version, NUL-terminated, for the installer to name the file by.
static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

/// # Safety
/// Returns a pointer to a static NUL-terminated string; nothing to free.
#[unsafe(no_mangle)]
pub extern "C" fn SkakelVirtualCameraVersion() -> *const c_char {
    VERSION.as_ptr().cast()
}

/// # Safety
/// Called by COM with valid pointers.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllGetClassObject(
    clsid: *const GUID,
    iid: *const GUID,
    out: *mut *mut c_void,
) -> HRESULT {
    if clsid.is_null() || iid.is_null() || out.is_null() {
        return E_POINTER;
    }
    guard_hresult("DllGetClassObject", || unsafe {
        *out = std::ptr::null_mut();
        if *clsid != GUID::from_u128(SOURCE_CLSID) {
            return CLASS_E_CLASSNOTAVAILABLE;
        }
        let factory: IUnknown = factory::ClassFactory::new().into();
        factory.query(iid, out)
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    if OBJECTS.load(Ordering::SeqCst) == 0 && LOCKS.load(Ordering::SeqCst) == 0 {
        S_OK
    } else {
        S_FALSE
    }
}

/// `regsvr32` support: points the CLSID at this file. The installer does the same after copying the
/// file to Program Files under its versioned name.
#[unsafe(no_mangle)]
pub extern "system" fn DllRegisterServer() -> HRESULT {
    guard_hresult("DllRegisterServer", || {
        match own_path()
            .and_then(|path| skakel_vcam::install::register(&path).map_err(|e| e.to_string()))
        {
            Ok(()) => S_OK,
            Err(e) => {
                log(&format!("DllRegisterServer failed: {e}"));
                SELFREG_E_CLASS
            }
        }
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn DllUnregisterServer() -> HRESULT {
    guard_hresult(
        "DllUnregisterServer",
        || match skakel_vcam::install::unregister() {
            Ok(()) => S_OK,
            Err(e) => {
                log(&format!("DllUnregisterServer failed: {e}"));
                SELFREG_E_CLASS
            }
        },
    )
}

/// This DLL's own path.
fn own_path() -> Result<std::path::PathBuf, String> {
    unsafe {
        let mut module = HMODULE::default();
        let anchor = DllCanUnloadNow as *const c_void;
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            PCWSTR(anchor.cast()),
            &mut module,
        )
        .map_err(|e| e.to_string())?;
        let mut buffer = vec![0u16; 32_768];
        let len = GetModuleFileNameW(Some(module), &mut buffer) as usize;
        if len == 0 {
            return Err(windows::core::Error::from_thread().to_string());
        }
        Ok(std::path::PathBuf::from(String::from_utf16_lossy(
            &buffer[..len],
        )))
    }
}

/// The source loaded in the test process through its own `DllGetClassObject`, the way Microsoft's
/// sample tests theirs: nothing is registered and no camera is created. Without a camera id it sends
/// the built-in idle frame, which is all these tests need to check the COM objects and the pacing.
#[cfg(test)]
mod tests {
    use std::time::Instant;

    use windows::Win32::Media::MediaFoundation::*;
    use windows::Win32::System::Com::IClassFactory;
    use windows::Win32::System::Com::StructuredStorage::PROPVARIANT;
    use windows::core::{GUID, IUnknown, Interface};

    use super::*;
    use skakel_vcam::contract::attributes;
    use skakel_vcam::convert::luma;

    const MF_VERSION: u32 = 0x0002_0070;

    #[test]
    fn a_panic_in_a_com_body_becomes_an_error_not_an_abort() {
        let failed: windows::core::Result<()> = guard("test", || panic!("boom"));
        assert_eq!(failed.unwrap_err().code(), E_FAIL);
        assert_eq!(guard("test", || Ok(5)).unwrap(), 5);
        let hr = guard_hresult("test", || panic!("boom"));
        assert_eq!(hr, E_FAIL);
    }

    #[test]
    fn a_poisoned_lock_is_still_usable() {
        let mutex = Mutex::new(1);
        let _ = std::thread::scope(|s| {
            s.spawn(|| {
                let _guard = mutex.lock().unwrap();
                panic!("poison it");
            })
            .join()
        });
        assert!(mutex.is_poisoned());
        assert_eq!(*lock(&mutex), 1);
    }

    struct Started;

    impl Started {
        fn new() -> Self {
            unsafe { MFStartup(MF_VERSION, MFSTARTUP_LITE).unwrap() };
            Started
        }
    }

    impl Drop for Started {
        fn drop(&mut self) {
            unsafe {
                let _ = MFShutdown();
            }
        }
    }

    fn activate(width: u32, height: u32, fps: u32) -> IMFActivate {
        unsafe {
            let mut raw = std::ptr::null_mut();
            DllGetClassObject(
                &GUID::from_u128(SOURCE_CLSID),
                &IClassFactory::IID,
                &mut raw,
            )
            .ok()
            .unwrap();
            let factory = IClassFactory::from_raw(raw);
            let activate: IMFActivate = factory.CreateInstance(None).unwrap();
            activate
                .SetUINT32(&GUID::from_u128(attributes::WIDTH), width)
                .unwrap();
            activate
                .SetUINT32(&GUID::from_u128(attributes::HEIGHT), height)
                .unwrap();
            activate
                .SetUINT64(
                    &GUID::from_u128(attributes::FRAME_RATE),
                    (u64::from(fps) << 32) | 1,
                )
                .unwrap();
            activate
        }
    }

    fn next_event(generator: &IMFMediaEventGenerator) -> (u32, PROPVARIANT) {
        unsafe {
            let event = generator
                .GetEvent(MEDIA_EVENT_GENERATOR_GET_EVENT_FLAGS(0))
                .unwrap();
            (event.GetType().unwrap(), event.GetValue().unwrap())
        }
    }

    #[test]
    fn refuses_a_class_it_does_not_serve() {
        let mut raw = std::ptr::null_mut();
        let hr = unsafe { DllGetClassObject(&GUID::from_u128(1), &IClassFactory::IID, &mut raw) };
        assert_eq!(hr, CLASS_E_CLASSNOTAVAILABLE);
        assert!(raw.is_null());
    }

    #[test]
    fn reports_its_version() {
        let version = unsafe { std::ffi::CStr::from_ptr(SkakelVirtualCameraVersion()) };
        assert_eq!(version.to_str().unwrap(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn offers_one_nv12_stream_at_the_cameras_size() {
        let _mf = Started::new();
        unsafe {
            let source: IMFMediaSourceEx = activate(640, 360, 60).ActivateObject().unwrap();
            assert_eq!(
                source.GetCharacteristics().unwrap(),
                MFMEDIASOURCE_IS_LIVE.0 as u32
            );
            let descriptor = source.CreatePresentationDescriptor().unwrap();
            assert_eq!(descriptor.GetStreamDescriptorCount().unwrap(), 1);
            let (mut selected, mut stream) = (Default::default(), None);
            descriptor
                .GetStreamDescriptorByIndex(0, &mut selected, &mut stream)
                .unwrap();
            let media_type = stream
                .unwrap()
                .GetMediaTypeHandler()
                .unwrap()
                .GetCurrentMediaType()
                .unwrap();
            assert_eq!(
                media_type.GetGUID(&MF_MT_SUBTYPE).unwrap(),
                MFVideoFormat_NV12
            );
            assert_eq!(
                media_type.GetUINT64(&MF_MT_FRAME_SIZE).unwrap(),
                (640 << 32) | 360
            );
            assert_eq!(
                media_type.GetUINT64(&MF_MT_FRAME_RATE).unwrap(),
                (60 << 32) | 1
            );
            let attributes = source.GetStreamAttributes(0).unwrap();
            assert_eq!(
                attributes
                    .GetUINT32(&MF_DEVICESTREAM_FRAMESERVER_SHARED)
                    .unwrap(),
                1
            );
            assert!(
                source
                    .GetSourceAttributes()
                    .unwrap()
                    .GetUnknown::<IUnknown>(&MF_DEVICEMFT_SENSORPROFILE_COLLECTION)
                    .is_ok()
            );
            source.Shutdown().unwrap();
            assert_eq!(
                source.CreatePresentationDescriptor().unwrap_err().code(),
                MF_E_SHUTDOWN
            );
        }
    }

    #[test]
    fn sends_samples_at_the_cameras_rate_with_steady_times() {
        let _mf = Started::new();
        unsafe {
            let source: IMFMediaSource = activate(64, 32, 30).ActivateObject().unwrap();
            let descriptor = source.CreatePresentationDescriptor().unwrap();
            descriptor.SelectStream(0).unwrap();
            source
                .Start(&descriptor, std::ptr::null(), &PROPVARIANT::default())
                .unwrap();

            let (kind, value) = next_event(&source.cast().unwrap());
            assert_eq!(kind, MENewStream.0 as u32);
            let stream: IMFMediaStream = IUnknown::try_from(&value).unwrap().cast().unwrap();
            assert_eq!(
                next_event(&source.cast().unwrap()).0,
                MESourceStarted.0 as u32
            );
            let stream_events: IMFMediaEventGenerator = stream.cast().unwrap();
            assert_eq!(next_event(&stream_events).0, MEStreamStarted.0 as u32);

            // Ask for six at once: they must still come one a frame, not in a burst.
            let asked = Instant::now();
            for _ in 0..6 {
                stream.RequestSample(None).unwrap();
            }
            let mut times = Vec::new();
            for _ in 0..6 {
                let (kind, value) = next_event(&stream_events);
                assert_eq!(kind, MEMediaSample.0 as u32);
                let sample: IMFSample = IUnknown::try_from(&value).unwrap().cast().unwrap();
                let duration = sample.GetSampleDuration().unwrap();
                assert!(
                    (333_333..=333_334).contains(&duration),
                    "duration {duration}"
                );
                times.push(sample.GetSampleTime().unwrap());
                let buffer = sample.ConvertToContiguousBuffer().unwrap();
                let (mut data, mut len) = (std::ptr::null_mut(), 0);
                buffer.Lock(&mut data, None, Some(&mut len)).unwrap();
                let bytes = std::slice::from_raw_parts(data, len as usize);
                assert_eq!(len, 64 * 32 * 3 / 2);
                assert!(
                    bytes[..64 * 32].iter().all(|&y| y == luma(24, 24, 24)),
                    "not the idle frame"
                );
                buffer.Unlock().unwrap();
            }
            let elapsed = asked.elapsed();
            assert!(
                elapsed.as_millis() >= 140,
                "six samples came in {elapsed:?}"
            );
            // Whole frames apart on one grid: k / 30 s from the first, rounded down to 100 ns.
            let first = times[0];
            for time in &times[1..] {
                let frames = ((time - first) as f64 / 333_333.33).round() as i64;
                assert!(
                    frames >= 1 && (time - first - frames * 10_000_000 / 30).abs() <= 1,
                    "sample times {times:?}"
                );
            }

            source.Stop().unwrap();
            source.Shutdown().unwrap();
        }
    }
}
