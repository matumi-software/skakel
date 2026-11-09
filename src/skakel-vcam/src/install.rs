//! Installing the media source: copy the DLL into Program Files under a versioned name and register
//! its CLSID machine-wide. Both need an elevated process.
//!
//! Frame Server keeps the DLL loaded while a camera made from it is in use, so the file cannot be
//! replaced in place. Each version therefore gets its own file name, `skakel_vcam_source-<version>.dll`;
//! the CLSID stays the same and is pointed at the newest file, and older files are deleted, or at the
//! next restart when they are still loaded.

use std::ffi::{CStr, c_char};
use std::path::{Path, PathBuf};

use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, FreeLibrary, WIN32_ERROR};
use windows::Win32::Storage::FileSystem::{MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ, RRF_RT_REG_SZ,
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegGetValueW, RegSetValueExW,
};
use windows::core::{HSTRING, PCWSTR, s};

use crate::contract::SOURCE_CLSID_STRING;
use crate::{Error, Result, sys};

/// The export every media source DLL has that says its version.
pub const VERSION_EXPORT: &str = "SkakelVirtualCameraVersion";

/// What the DLL is called before the installer renames it: cargo's name for the cdylib.
pub const BUILD_FILE_NAME: &str = "skakel_vcam_source.dll";

const FILE_PREFIX: &str = "skakel_vcam_source-";

fn clsid_key() -> String {
    format!("Software\\Classes\\CLSID\\{SOURCE_CLSID_STRING}")
}

/// `%ProgramFiles%\Skakel\VirtualCamera`, where the installer puts the DLL. Frame Server's service
/// accounts can read it, which they cannot in a user's profile.
pub fn install_folder() -> Result<PathBuf> {
    Ok(sys::program_files()?.join("Skakel").join("VirtualCamera"))
}

/// The file name a version is installed as.
pub fn versioned_file_name(version: &str) -> String {
    format!("{FILE_PREFIX}{version}.dll")
}

/// The version a media source DLL reports, by loading it and calling its version export.
pub fn dll_version(dll: &Path) -> Result<String> {
    type Version = unsafe extern "C" fn() -> *const c_char;
    unsafe {
        let module = LoadLibraryW(&HSTRING::from(dll.as_os_str()))?;
        let result = match GetProcAddress(module, s!("SkakelVirtualCameraVersion")) {
            Some(export) => {
                let version: Version = std::mem::transmute(export);
                Ok(CStr::from_ptr(version()).to_string_lossy().into_owned())
            }
            None => Err(Error::InvalidArgument(format!(
                "{} is not a Skakel virtual camera source: it has no {VERSION_EXPORT}",
                dll.display()
            ))),
        };
        let _ = FreeLibrary(module);
        result
    }
}

/// Points the CLSID at `dll`: `InprocServer32` with `ThreadingModel` `Both`, under HKLM, where Frame
/// Server looks.
pub fn register(dll: &Path) -> Result<()> {
    unsafe {
        let class = create_key(&clsid_key())?;
        let result = set_string(class, None, "Skakel virtual camera source");
        let _ = RegCloseKey(class);
        result?;
        let server = create_key(&format!("{}\\InprocServer32", clsid_key()))?;
        let result = set_string(server, None, &dll.to_string_lossy())
            .and_then(|()| set_string(server, Some("ThreadingModel"), "Both"));
        let _ = RegCloseKey(server);
        result
    }
}

/// Removes the CLSID. Cameras made from it stop working.
pub fn unregister() -> Result<()> {
    let status = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, &HSTRING::from(clsid_key())) };
    if status == ERROR_FILE_NOT_FOUND {
        Ok(())
    } else {
        win32(status)
    }
}

/// The DLL the CLSID points at, or None when it is not registered.
pub fn registered_path() -> Result<Option<PathBuf>> {
    let key = HSTRING::from(format!("{}\\InprocServer32", clsid_key()));
    let mut buffer = vec![0u16; 1024];
    let mut len = (buffer.len() * 2) as u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            &key,
            PCWSTR::null(),
            RRF_RT_REG_SZ,
            None,
            Some(buffer.as_mut_ptr().cast()),
            Some(&mut len),
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    win32(status)?;
    let chars = (len as usize / 2).saturating_sub(1);
    Ok(Some(PathBuf::from(String::from_utf16_lossy(
        &buffer[..chars],
    ))))
}

/// What `install` did.
#[derive(Debug)]
pub struct Installed {
    /// The file the CLSID points at now.
    pub path: PathBuf,
    pub version: String,
    /// Older versions still loaded, deleted at the next restart.
    pub pending_delete: Vec<PathBuf>,
}

/// Installs `dll` (a build of `skakel-vcam-source`) for every user: copies it into the install folder
/// under its versioned name, registers it, and removes older versions. An upgrade works while a camera
/// made from the old version is in use; that camera picks up the new version the next time it starts.
pub fn install(dll: &Path) -> Result<Installed> {
    require_elevation()?;
    let version = dll_version(dll)?;
    let folder = install_folder()?;
    std::fs::create_dir_all(&folder)?;
    let target = folder.join(versioned_file_name(&version));
    copy_unless_same(dll, &target)?;
    register(&target)?;
    let pending_delete = remove_versions_except(&folder, Some(&target))?;
    Ok(Installed {
        path: target,
        version,
        pending_delete,
    })
}

/// Unregisters the media source and deletes its files. Returns the files still loaded, which go at
/// the next restart. Cameras users created stay listed until each user removes theirs.
pub fn uninstall() -> Result<Vec<PathBuf>> {
    require_elevation()?;
    unregister()?;
    let folder = install_folder()?;
    if !folder.exists() {
        return Ok(Vec::new());
    }
    let pending = remove_versions_except(&folder, None)?;
    if pending.is_empty() {
        let _ = std::fs::remove_dir(&folder);
    }
    Ok(pending)
}

fn require_elevation() -> Result<()> {
    sys::check_supported()?;
    if sys::is_elevated()? {
        Ok(())
    } else {
        Err(Error::NotElevated)
    }
}

/// Copies unless the target holds the same bytes already, which it may while it is loaded.
fn copy_unless_same(source: &Path, target: &Path) -> Result<()> {
    if target.exists() && std::fs::read(source)? == std::fs::read(target)? {
        return Ok(());
    }
    std::fs::copy(source, target).map_err(|e| {
        Error::InvalidArgument(format!(
            "could not write {}: {e}. If this version is loaded with other contents, build it with a new version number",
            target.display()
        ))
    })?;
    Ok(())
}

/// Deletes every versioned DLL in `folder` but `keep`; schedules the ones in use for the next restart.
fn remove_versions_except(folder: &Path, keep: Option<&Path>) -> Result<Vec<PathBuf>> {
    let mut pending = Vec::new();
    for entry in std::fs::read_dir(folder)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !is_versioned_file_name(&name) || keep.is_some_and(|k| k == path) {
            continue;
        }
        if std::fs::remove_file(&path).is_err() {
            unsafe {
                MoveFileExW(
                    &HSTRING::from(path.as_os_str()),
                    PCWSTR::null(),
                    MOVEFILE_DELAY_UNTIL_REBOOT,
                )?
            };
            pending.push(path);
        }
    }
    Ok(pending)
}

/// True for a name `versioned_file_name` makes.
pub fn is_versioned_file_name(name: &str) -> bool {
    name.len() > FILE_PREFIX.len() + 4
        && name.starts_with(FILE_PREFIX)
        && name.to_ascii_lowercase().ends_with(".dll")
}

unsafe fn create_key(path: &str) -> Result<HKEY> {
    let mut key = HKEY::default();
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            &HSTRING::from(path),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut key,
            None,
        )
    };
    win32(status)?;
    Ok(key)
}

unsafe fn set_string(key: HKEY, name: Option<&str>, value: &str) -> Result<()> {
    let data: Vec<u8> = value
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    let name = name.map(HSTRING::from);
    let name = name.as_ref().map_or(PCWSTR::null(), |n| PCWSTR(n.as_ptr()));
    win32(unsafe { RegSetValueExW(key, name, None, REG_SZ, Some(&data)) })
}

fn win32(status: WIN32_ERROR) -> Result<()> {
    status.ok().map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_each_version_apart() {
        assert_eq!(versioned_file_name("0.2.0"), "skakel_vcam_source-0.2.0.dll");
        assert!(is_versioned_file_name("skakel_vcam_source-0.2.0.dll"));
        assert!(is_versioned_file_name(
            "skakel_vcam_source-0.3.0-beta.1.DLL"
        ));
        assert!(!is_versioned_file_name("skakel_vcam_source.dll"));
        assert!(!is_versioned_file_name("skakel_vcam_source-.dll"));
        assert!(!is_versioned_file_name("other.dll"));
    }

    #[test]
    fn registers_under_the_fixed_clsid() {
        assert_eq!(
            clsid_key(),
            "Software\\Classes\\CLSID\\{8138410C-B0A8-4CBC-9E0E-5920362ED550}"
        );
    }
}
