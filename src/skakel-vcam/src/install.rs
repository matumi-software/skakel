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
    /// Older versions that could neither be deleted nor scheduled for deletion. They do no harm;
    /// delete them by hand.
    pub left_behind: Vec<PathBuf>,
}

/// What `remove_versions_except` did with the files it found.
struct Removal {
    /// Still loaded: deleted at the next restart.
    pending: Vec<PathBuf>,
    /// Neither deleted nor scheduled.
    failed: Vec<(PathBuf, String)>,
}

/// Installs `dll` (a build of `skakel-vcam-source`) for every user: copies it into the install folder
/// under its versioned name, registers it, and removes older versions. An upgrade works while a camera
/// made from the old version is in use; that camera picks up the new version the next time it starts.
///
/// The DLL is copied into the install folder first, which only administrators can write, and the
/// copy is what is loaded to read its version and what is installed. Loading the file where the
/// caller left it, and copying it afterwards, would install bytes other than the ones that were
/// checked if someone else could write there in between.
pub fn install(dll: &Path) -> Result<Installed> {
    require_elevation()?;
    let folder = install_folder()?;
    std::fs::create_dir_all(&folder)?;
    let incoming = folder.join(format!("incoming-{}.tmp", std::process::id()));
    std::fs::copy(dll, &incoming).map_err(|e| {
        Error::InvalidArgument(format!(
            "could not copy {} into {}: {e}",
            dll.display(),
            folder.display()
        ))
    })?;
    let placed = place(&incoming, &folder);
    // A temporary that was not moved is not wanted, whatever went wrong.
    let _ = std::fs::remove_file(&incoming);
    let (version, target) = placed?;
    register(&target)?;
    let removal = remove_versions_except(&folder, Some(&target))?;
    Ok(Installed {
        path: target,
        version,
        pending_delete: removal.pending,
        left_behind: removal.failed.into_iter().map(|(path, _)| path).collect(),
    })
}

/// Reads the version of the DLL at `incoming` and gives it its versioned name in `folder`, unless a
/// file of that name holds the same bytes already (it may, while it is loaded).
fn place(incoming: &Path, folder: &Path) -> Result<(String, PathBuf)> {
    let version = dll_version(incoming)?;
    let target = folder.join(versioned_file_name(&version));
    if target.exists() && std::fs::read(incoming)? == std::fs::read(&target)? {
        return Ok((version, target));
    }
    std::fs::copy(incoming, &target).map_err(|e| {
        Error::InvalidArgument(format!(
            "could not write {}: {e}. If this version is loaded with other contents, build it with a new version number",
            target.display()
        ))
    })?;
    Ok((version, target))
}

/// Unregisters the media source and deletes its files. Returns the files still loaded, which go at
/// the next restart. Cameras users created stay listed until each user removes theirs.
///
/// Only a registration that points into the install folder is removed. The CLSID is machine-wide
/// and shared with whatever else registered it (`regsvr32` on a build of the DLL, an installer of
/// an app's own), so one that points elsewhere is left alone and reported: remove it with
/// `regsvr32 /u` on that file.
pub fn uninstall() -> Result<Vec<PathBuf>> {
    require_elevation()?;
    let folder = install_folder()?;
    if let Some(registered) = registered_path()?
        && !is_inside(&registered, &folder)
    {
        return Err(Error::InvalidArgument(format!(
            "the media source is registered from {}, not from {}, so it was not installed by this tool and is left registered. Run regsvr32 /u on that file to remove it",
            registered.display(),
            folder.display()
        )));
    }
    unregister()?;
    if !folder.exists() {
        return Ok(Vec::new());
    }
    let removal = remove_versions_except(&folder, None)?;
    if !removal.failed.is_empty() {
        let files: Vec<String> = removal
            .failed
            .iter()
            .map(|(path, why)| format!("{} ({why})", path.display()))
            .collect();
        return Err(Error::InvalidArgument(format!(
            "unregistered, but could not remove: {}",
            files.join(", ")
        )));
    }
    if removal.pending.is_empty() {
        let _ = std::fs::remove_dir(&folder);
    }
    Ok(removal.pending)
}

/// True when `file` is directly inside `folder`, by Windows' rules for paths: case does not matter,
/// and `/` and `\` are the same.
fn is_inside(file: &Path, folder: &Path) -> bool {
    let normal = |p: &Path| {
        p.to_string_lossy()
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_lowercase()
    };
    file.parent()
        .is_some_and(|parent| normal(parent) == normal(folder))
}

fn require_elevation() -> Result<()> {
    sys::check_supported()?;
    if sys::is_elevated()? {
        Ok(())
    } else {
        Err(Error::NotElevated)
    }
}

/// Deletes every versioned DLL in `folder` but `keep`; schedules the ones in use for the next restart.
/// One file that cannot be dealt with does not stop the others: it is reported in `failed`.
fn remove_versions_except(folder: &Path, keep: Option<&Path>) -> Result<Removal> {
    let mut removal = Removal {
        pending: Vec::new(),
        failed: Vec::new(),
    };
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
            let scheduled = unsafe {
                MoveFileExW(
                    &HSTRING::from(path.as_os_str()),
                    PCWSTR::null(),
                    MOVEFILE_DELAY_UNTIL_REBOOT,
                )
            };
            match scheduled {
                Ok(()) => removal.pending.push(path),
                Err(e) => removal.failed.push((path, e.to_string())),
            }
        }
    }
    Ok(removal)
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
    fn knows_a_file_in_the_install_folder_by_windows_rules() {
        let folder = Path::new(r"C:\Program Files\Skakel\VirtualCamera");
        assert!(is_inside(
            Path::new(r"C:\Program Files\Skakel\VirtualCamera\skakel_vcam_source-0.2.1.dll"),
            folder
        ));
        assert!(is_inside(
            Path::new(r"c:/program files/skakel/virtualcamera/a.dll"),
            folder
        ));
        assert!(is_inside(
            Path::new(r"C:\Program Files\Skakel\VirtualCamera\a.dll"),
            Path::new(r"C:\Program Files\Skakel\VirtualCamera\")
        ));
        // Elsewhere, below it, or beside it with a longer name.
        assert!(!is_inside(
            Path::new(r"D:\build\skakel_vcam_source.dll"),
            folder
        ));
        assert!(!is_inside(
            Path::new(r"C:\Program Files\Skakel\VirtualCamera\old\a.dll"),
            folder
        ));
        assert!(!is_inside(
            Path::new(r"C:\Program Files\Skakel\VirtualCamera2\a.dll"),
            folder
        ));
    }

    #[test]
    fn registers_under_the_fixed_clsid() {
        assert_eq!(
            clsid_key(),
            "Software\\Classes\\CLSID\\{8138410C-B0A8-4CBC-9E0E-5920362ED550}"
        );
    }
}
