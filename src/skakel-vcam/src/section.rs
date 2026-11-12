//! The shared memory as a Windows section object, `Global\Skakel.VirtualCamera.<id>`.
//!
//! The media source creates it: a section in the `Global\` namespace needs
//! `SeCreateGlobalPrivilege`, which the Frame Server's service accounts have and a user's app does
//! not. Its DACL lets the producer's user read and write it and nobody else but the system.

use std::ffi::c_void;

use windows::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, GetLastError, HLOCAL, INVALID_HANDLE_VALUE,
    LocalFree,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP_READ, FILE_MAP_WRITE, MEMORY_BASIC_INFORMATION,
    MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile, OpenFileMappingW, PAGE_READWRITE, UnmapViewOfFile,
    VirtualQuery,
};
use windows::core::HSTRING;

use crate::Result;
use crate::layout::Region;
use crate::sys::OwnedHandle;

/// A mapped view of a camera's shared memory.
pub struct Section {
    view: MEMORY_MAPPED_VIEW_ADDRESS,
    len: usize,
    _handle: OwnedHandle,
}

// The view is plain memory, reached only through `Region`; the handle may be closed on any thread.
unsafe impl Send for Section {}

/// The DACL the media source gives the section: full access for the system, administrators and the
/// Frame Server's account, read and write for the producer's user. Without a SID, every interactive
/// user may write it.
pub fn security_descriptor(producer_sid: Option<&str>) -> String {
    let producer = producer_sid.filter(|sid| is_sid(sid)).unwrap_or("IU");
    format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;LS)(A;;GRGW;;;{producer})")
}

/// True for text that looks like a SID, so an attribute cannot add ACEs of its own.
fn is_sid(text: &str) -> bool {
    text.starts_with("S-1-")
        && text.len() <= 184
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'-' || b == b'S')
}

impl Section {
    /// The producer's side: opens an existing section for reading and writing, or None when no media
    /// source has created it yet.
    pub fn open(name: &str) -> Result<Option<Self>> {
        let access = (FILE_MAP_READ | FILE_MAP_WRITE).0;
        let handle = match unsafe { OpenFileMappingW(access, false, &HSTRING::from(name)) } {
            Ok(handle) => OwnedHandle(handle),
            Err(e) if e.code() == ERROR_FILE_NOT_FOUND.to_hresult() => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        Self::map(handle, FILE_MAP_READ | FILE_MAP_WRITE).map(Some)
    }

    /// The media source's side: creates the section with `size` bytes, or opens it read-only when it
    /// exists already. Says which.
    pub fn create(name: &str, size: usize, producer_sid: Option<&str>) -> Result<(Self, bool)> {
        let name = HSTRING::from(name);
        let sddl = HSTRING::from(security_descriptor(producer_sid));
        unsafe {
            let mut descriptor = PSECURITY_DESCRIPTOR::default();
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                &sddl,
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )?;
            let attributes = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor.0,
                bInheritHandle: false.into(),
            };
            let size = size as u64;
            let created = CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                Some(&attributes),
                PAGE_READWRITE,
                (size >> 32) as u32,
                size as u32,
                &name,
            );
            let existed = GetLastError() == ERROR_ALREADY_EXISTS;
            LocalFree(Some(HLOCAL(descriptor.0)));
            match created {
                Ok(handle) if !existed => Ok((
                    Self::map(OwnedHandle(handle), FILE_MAP_READ | FILE_MAP_WRITE)?,
                    true,
                )),
                Ok(handle) => Ok((Self::map(OwnedHandle(handle), FILE_MAP_READ)?, false)),
                // Not allowed to create in Global\ (no SeCreateGlobalPrivilege): perhaps it exists.
                Err(_) => {
                    let handle = OpenFileMappingW(FILE_MAP_READ.0, false, &name)?;
                    Ok((Self::map(OwnedHandle(handle), FILE_MAP_READ)?, false))
                }
            }
        }
    }

    fn map(handle: OwnedHandle, access: windows::Win32::System::Memory::FILE_MAP) -> Result<Self> {
        unsafe {
            let view = MapViewOfFile(handle.0, access, 0, 0, 0);
            if view.Value.is_null() {
                return Err(windows::core::Error::from_thread().into());
            }
            let mut info = MEMORY_BASIC_INFORMATION::default();
            if VirtualQuery(
                Some(view.Value as *const c_void),
                &mut info,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            ) == 0
            {
                let error = windows::core::Error::from_thread();
                let _ = UnmapViewOfFile(view);
                return Err(error.into());
            }
            Ok(Self {
                view,
                len: info.RegionSize,
                _handle: handle,
            })
        }
    }

    /// The mapped bytes. Writable only when this side mapped it for writing.
    ///
    /// # Safety
    /// A `Region` is a `Copy` view with no lifetime: it stays valid only while this `Section` is
    /// alive. The caller must drop every `Region` made from it, and every `FrameWriter` or
    /// `FrameReader` built on one, before the `Section` is dropped (keep them in a struct with the
    /// section declared after them, as `VirtualCamera` does).
    pub unsafe fn region(&self) -> Region {
        // Mapped for as long as `self` lives, and page aligned; the caller keeps to that.
        unsafe { Region::new(self.view.Value.cast(), self.len) }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Drop for Section {
    fn drop(&mut self) {
        unsafe {
            let _ = UnmapViewOfFile(self.view);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grants_the_producer_read_and_write() {
        assert_eq!(
            security_descriptor(Some("S-1-5-21-1-2-3-1001")),
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;LS)(A;;GRGW;;;S-1-5-21-1-2-3-1001)"
        );
    }

    #[test]
    fn falls_back_to_interactive_users_for_anything_but_a_sid() {
        assert!(security_descriptor(None).ends_with("(A;;GRGW;;;IU)"));
        assert!(security_descriptor(Some("S-1-1-0)(A;;GA;;;WD")).ends_with("(A;;GRGW;;;IU)"));
    }
}
