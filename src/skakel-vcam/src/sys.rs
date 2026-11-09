//! The few Windows calls the producer and the installer share: the Windows build, the user's SID,
//! known folders, elevation, and Media Foundation loaded at run time.

use std::ffi::c_void;
use std::path::PathBuf;

use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenUser,
};
use windows::Win32::System::Com::{
    COINIT_MULTITHREADED, CoInitializeEx, CoTaskMemFree, CoUninitialize,
};
use windows::Win32::System::LibraryLoader::{
    GetModuleHandleW, GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows::Win32::System::SystemInformation::OSVERSIONINFOW;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::{
    FOLDERID_ProgramData, FOLDERID_ProgramFiles, KNOWN_FOLDER_FLAG, SHGetKnownFolderPath,
};
use windows::core::{GUID, HRESULT, PCWSTR, PWSTR, s, w};

use crate::{Error, Result};

/// The first Windows build with `MFCreateVirtualCamera`: Windows 11.
pub const MIN_BUILD: u32 = 22000;

/// The Windows build number, from `RtlGetVersion`, which does not lie about it the way
/// `GetVersionEx` does to unmanifested programs.
pub fn windows_build() -> u32 {
    type RtlGetVersion = unsafe extern "system" fn(*mut OSVERSIONINFOW) -> i32;
    unsafe {
        let Ok(ntdll) = GetModuleHandleW(w!("ntdll.dll")) else {
            return 0;
        };
        let Some(proc) = GetProcAddress(ntdll, s!("RtlGetVersion")) else {
            return 0;
        };
        let rtl_get_version: RtlGetVersion = std::mem::transmute(proc);
        let mut info = OSVERSIONINFOW {
            dwOSVersionInfoSize: size_of::<OSVERSIONINFOW>() as u32,
            ..Default::default()
        };
        if rtl_get_version(&mut info) == 0 {
            info.dwBuildNumber
        } else {
            0
        }
    }
}

/// Ok on Windows 11, `Error::Unsupported` before it.
pub fn check_supported() -> Result<()> {
    let build = windows_build();
    if build >= MIN_BUILD {
        Ok(())
    } else {
        Err(Error::Unsupported(format!(
            "the virtual camera needs Windows 11 (build {MIN_BUILD} or later); this is build {build}"
        )))
    }
}

fn invalid_text(e: std::string::FromUtf16Error) -> Error {
    Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Closes a handle when dropped.
pub(crate) struct OwnedHandle(pub(crate) HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

fn token_information(class: windows::Win32::Security::TOKEN_INFORMATION_CLASS) -> Result<Vec<u64>> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;
        let token = OwnedHandle(token);
        let mut len = 0u32;
        // The first call only says how big the buffer must be.
        let _ = GetTokenInformation(token.0, class, None, 0, &mut len);
        // u64 so the structures in it are aligned.
        let mut buffer = vec![0u64; (len as usize).div_ceil(8)];
        GetTokenInformation(
            token.0,
            class,
            Some(buffer.as_mut_ptr().cast()),
            len,
            &mut len,
        )?;
        Ok(buffer)
    }
}

/// The SID of the user this process runs as, in `S-1-5-...` form.
pub fn current_user_sid() -> Result<String> {
    let buffer = token_information(TokenUser)?;
    unsafe {
        let user = &*(buffer.as_ptr() as *const TOKEN_USER);
        let mut text = PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut text)?;
        let sid = text.to_string();
        LocalFree(Some(HLOCAL(text.0.cast())));
        sid.map_err(invalid_text)
    }
}

/// True when this process runs elevated.
pub fn is_elevated() -> Result<bool> {
    let buffer = token_information(TokenElevation)?;
    let elevation = unsafe { &*(buffer.as_ptr() as *const TOKEN_ELEVATION) };
    Ok(elevation.TokenIsElevated != 0)
}

fn known_folder(id: &GUID) -> Result<PathBuf> {
    unsafe {
        let path = SHGetKnownFolderPath(id, KNOWN_FOLDER_FLAG(0), None)?;
        let text = path.to_string();
        CoTaskMemFree(Some(path.0 as *const c_void));
        Ok(PathBuf::from(text.map_err(invalid_text)?))
    }
}

/// `%ProgramData%`.
pub fn program_data() -> Result<PathBuf> {
    known_folder(&FOLDERID_ProgramData)
}

/// `%ProgramFiles%`, the 64-bit one in a 64-bit process.
pub fn program_files() -> Result<PathBuf> {
    known_folder(&FOLDERID_ProgramFiles)
}

type MfStartup = unsafe extern "system" fn(u32, u32) -> HRESULT;
type MfShutdown = unsafe extern "system" fn() -> HRESULT;
type MfCreateVirtualCamera = unsafe extern "system" fn(
    i32,
    i32,
    i32,
    PCWSTR,
    PCWSTR,
    *const GUID,
    u32,
    *mut *mut c_void,
) -> HRESULT;

/// `MF_VERSION` from mfapi.h.
const MF_VERSION: u32 = 0x0002_0070;
/// `MFSTARTUP_LITE`: no sockets, which the camera calls do not need.
const MFSTARTUP_LITE: u32 = 1;

/// Media Foundation, loaded at run time so a program that links this crate still starts on Windows
/// 10 and on Windows N editions without the Media Feature Pack, and only the camera calls fail.
/// Started on creation and shut down on drop, with COM initialised on the thread for as long.
pub(crate) struct MediaFoundation {
    create_virtual_camera: MfCreateVirtualCamera,
    shutdown: MfShutdown,
    uninitialize_com: bool,
}

impl MediaFoundation {
    pub(crate) fn start() -> Result<Self> {
        check_supported()?;
        unsafe {
            let mfplat = LoadLibraryExW(w!("mfplat.dll"), None, LOAD_LIBRARY_SEARCH_SYSTEM32)
                .map_err(|e| {
                    Error::Unsupported(format!("Media Foundation is not installed: {e}"))
                })?;
            let sensor =
                LoadLibraryExW(w!("mfsensorgroup.dll"), None, LOAD_LIBRARY_SEARCH_SYSTEM32)
                    .map_err(|e| {
                        Error::Unsupported(format!("mfsensorgroup.dll is missing: {e}"))
                    })?;
            let missing =
                |name: &str| Error::Unsupported(format!("{name} is missing from this Windows"));
            let startup: MfStartup = std::mem::transmute(
                GetProcAddress(mfplat, s!("MFStartup")).ok_or_else(|| missing("MFStartup"))?,
            );
            let shutdown: MfShutdown = std::mem::transmute(
                GetProcAddress(mfplat, s!("MFShutdown")).ok_or_else(|| missing("MFShutdown"))?,
            );
            let create_virtual_camera: MfCreateVirtualCamera = std::mem::transmute(
                GetProcAddress(sensor, s!("MFCreateVirtualCamera"))
                    .ok_or_else(|| missing("MFCreateVirtualCamera"))?,
            );
            // S_OK or S_FALSE: ours to undo. RPC_E_CHANGED_MODE: the thread is STA already, which
            // works too, and is not ours to undo.
            let uninitialize_com = CoInitializeEx(None, COINIT_MULTITHREADED).is_ok();
            if let Err(e) = startup(MF_VERSION, MFSTARTUP_LITE).ok() {
                if uninitialize_com {
                    CoUninitialize();
                }
                return Err(e.into());
            }
            Ok(Self {
                create_virtual_camera,
                shutdown,
                uninitialize_com,
            })
        }
    }

    /// `MFCreateVirtualCamera` for a software camera with the given lifetime and access.
    pub(crate) fn create_virtual_camera(
        &self,
        lifetime: i32,
        access: i32,
        friendly_name: &str,
        source_id: &str,
    ) -> Result<windows::Win32::Media::MediaFoundation::IMFVirtualCamera> {
        use windows::Win32::Media::MediaFoundation::{
            IMFVirtualCamera, MFVirtualCameraType_SoftwareCameraSource,
        };
        use windows::core::{HSTRING, Interface};
        let name = HSTRING::from(friendly_name);
        let source = HSTRING::from(source_id);
        let mut camera = std::ptr::null_mut();
        unsafe {
            (self.create_virtual_camera)(
                MFVirtualCameraType_SoftwareCameraSource.0,
                lifetime,
                access,
                PCWSTR(name.as_ptr()),
                PCWSTR(source.as_ptr()),
                std::ptr::null(),
                0,
                &mut camera,
            )
            .ok()?;
            Ok(IMFVirtualCamera::from_raw(camera))
        }
    }
}

impl Drop for MediaFoundation {
    fn drop(&mut self) {
        unsafe {
            let _ = (self.shutdown)();
            if self.uninitialize_com {
                CoUninitialize();
            }
        }
    }
}
