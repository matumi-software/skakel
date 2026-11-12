//! The shared memory as a Windows section object, `Global\Skakel.VirtualCamera.<id>`.
//!
//! The media source creates it: a section in the `Global\` namespace needs
//! `SeCreateGlobalPrivilege`, which the Frame Server's service accounts have and a user's app does
//! not. Its DACL lets the producer's user read and write it and nobody else but the system. A source
//! that finds the section already there reads its DACL and uses it only when it is that one (see
//! `Section::create`), so a camera made with another user's id cannot show that user's frames.

use std::ffi::c_void;

use windows::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, GetLastError, HANDLE, HLOCAL,
    INVALID_HANDLE_VALUE, LocalFree,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_KERNEL_OBJECT,
};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
    DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES,
};
use windows::Win32::Storage::FileSystem::READ_CONTROL;
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

/// The DACL the media source gives the section: full access for the system and administrators, read
/// and write for the Frame Server's account (Local Service, which needs to map it and nothing more:
/// full access would also let any Local Service process change the DACL and the owner) and for the
/// producer's user. Without a usable SID, every interactive user may write it.
pub fn security_descriptor(producer_sid: Option<&str>) -> String {
    let producer = producer_sid.filter(|sid| is_user_sid(sid)).unwrap_or("IU");
    format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;LS)(A;;GRGW;;;{producer})")
}

/// True for the SID of one account: `S-1-<authority>` and 4 to 15 sub-authorities, all numbers, such
/// as `S-1-5-21-a-b-c-rid` or an Entra ID user's `S-1-12-1-a-b-c-d`. The SID comes from an attribute
/// of the camera, which any user can set, so it must not be able to name a group everyone is in:
/// Everyone (`S-1-1-0`), Authenticated Users (`S-1-5-11`), Interactive (`S-1-5-4`), the
/// `BUILTIN\Users` group (`S-1-5-32-545`) and the rest have one or two sub-authorities, an account
/// has at least four. It also keeps the text from adding ACEs of its own.
fn is_user_sid(text: &str) -> bool {
    let Some(rest) = text.strip_prefix("S-1-") else {
        return false;
    };
    let number = |p: &str| !p.is_empty() && p.len() <= 10 && p.bytes().all(|b| b.is_ascii_digit());
    let mut parts = rest.split('-');
    let authority = parts.next().is_some_and(number);
    let subs: Vec<&str> = parts.collect();
    authority && (4..=15).contains(&subs.len()) && subs.iter().all(|p| number(p))
}

/// Whether the SIDs in a section's DACL are the ones `security_descriptor(producer_sid)` puts there
/// (the producer's among them), and nobody else's.
fn dacl_is_ours(sids: &[String], producer_sid: Option<&str>) -> bool {
    let producer = producer_sid
        .filter(|sid| is_user_sid(sid))
        .unwrap_or("S-1-5-4");
    let allowed = ["S-1-5-18", "S-1-5-32-544", "S-1-5-19", producer];
    sids.iter()
        .all(|sid| allowed.iter().any(|a| a.eq_ignore_ascii_case(sid)))
        && sids.iter().any(|sid| producer.eq_ignore_ascii_case(sid))
}

/// The SIDs of the access-allowed entries in the DACL of the object `handle` (which needs
/// `READ_CONTROL`). Any other kind of entry is reported as `"?"`, which `dacl_is_ours` refuses.
fn dacl_sids(handle: HANDLE) -> Result<Vec<String>> {
    unsafe {
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let status = GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            Some(&mut descriptor),
        );
        if status != ERROR_SUCCESS {
            return Err(windows::core::Error::from(status.to_hresult()).into());
        }
        // The DACL lives in the descriptor, freed once the SIDs are copied out.
        let sids = (|| -> Result<Vec<String>> {
            if dacl.is_null() {
                // No DACL means everyone has access.
                return Ok(vec!["?".to_owned()]);
            }
            let mut size = ACL_SIZE_INFORMATION::default();
            GetAclInformation(
                dacl,
                (&mut size as *mut ACL_SIZE_INFORMATION).cast(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )?;
            let mut sids = Vec::new();
            for index in 0..size.AceCount {
                let mut ace: *mut c_void = std::ptr::null_mut();
                GetAce(dacl, index, &mut ace)?;
                // ACCESS_ALLOWED_ACE_TYPE is 0.
                if (*ace.cast::<ACE_HEADER>()).AceType != 0 {
                    sids.push("?".to_owned());
                    continue;
                }
                let sid = PSID(
                    std::ptr::addr_of_mut!((*ace.cast::<ACCESS_ALLOWED_ACE>()).SidStart).cast(),
                );
                let mut text = windows::core::PWSTR::null();
                ConvertSidToStringSidW(sid, &mut text)?;
                sids.push(text.to_string().unwrap_or_else(|_| "?".to_owned()));
                LocalFree(Some(HLOCAL(text.0.cast())));
            }
            Ok(sids)
        })();
        LocalFree(Some(HLOCAL(descriptor.0)));
        sids
    }
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
    ///
    /// A section that exists already is used only when its DACL has the entries `security_descriptor`
    /// would give it for `producer_sid`, and no others. Anyone can create a camera with any id, so
    /// without that a user could open another user's section through a camera of their own and show
    /// that user's frames. An existing section that fails the check is an error
    /// (`PermissionDenied`). It does not stop a user creating a section first, under a camera id
    /// they computed for someone else, which only keeps that camera from working (see
    /// `docs/virtual-camera.md`).
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
                // It exists already, or we may not create it in Global\ (no SeCreateGlobalPrivilege)
                // and perhaps it exists. Either way, open it again with just the access needed, and
                // check whose it is.
                other => {
                    drop(other.map(OwnedHandle));
                    Self::open_existing(&name, producer_sid)
                }
            }
        }
    }

    /// Opens a section that exists, read-only, after checking its DACL against `producer_sid`.
    fn open_existing(name: &HSTRING, producer_sid: Option<&str>) -> Result<(Self, bool)> {
        let handle = unsafe {
            OpenFileMappingW(FILE_MAP_READ.0 | READ_CONTROL.0, false, name).map(OwnedHandle)?
        };
        let sids = dacl_sids(handle.0)?;
        if !dacl_is_ours(&sids, producer_sid) {
            return Err(crate::Error::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "the section {name} exists with access for {sids:?}, not for this camera's producer"
                ),
            )));
        }
        Ok((Self::map(handle, FILE_MAP_READ)?, false))
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

    /// The length of the mapping in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// True for a mapping of no bytes.
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
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;LS)(A;;GRGW;;;S-1-5-21-1-2-3-1001)"
        );
    }

    #[test]
    fn local_service_can_map_the_section_but_not_change_who_may() {
        let sddl = security_descriptor(None);
        assert!(sddl.contains("(A;;GRGW;;;LS)"));
        assert!(!sddl.contains("(A;;GA;;;LS)"));
    }

    #[test]
    fn refuses_the_sid_of_a_group_everyone_is_in() {
        for group in [
            "S-1-1-0",      // Everyone
            "S-1-5-11",     // Authenticated Users
            "S-1-5-4",      // Interactive
            "S-1-5-2",      // Network
            "S-1-5-7",      // Anonymous
            "S-1-2-1",      // Console logon
            "S-1-5-32-545", // BUILTIN\Users
            "S-1-5-32-546", // BUILTIN\Guests
        ] {
            assert!(!is_user_sid(group), "{group}");
            assert!(
                security_descriptor(Some(group)).ends_with("(A;;GRGW;;;IU)"),
                "{group}"
            );
        }
    }

    #[test]
    fn takes_the_sid_of_one_account() {
        for account in [
            "S-1-5-21-1004336348-1177238915-682003330-512",
            "S-1-5-21-1-2-3-1001",
            "S-1-12-1-1-2-3-4",
            "S-1-5-80-1-2-3-4-5",
        ] {
            assert!(is_user_sid(account), "{account}");
        }
        for bad in [
            "",
            "S-1-",
            "S-1-5-21-1-2-3-",
            "S-1-5-21-1-2-3-x",
            "S-1-5-21-1-2-3-1)(A;;GA;;;WD",
            "S-2-5-21-1-2-3-4",
            "s-1-5-21-1-2-3-4",
            "S-1-5-21-1-2-3-99999999999",
        ] {
            assert!(!is_user_sid(bad), "{bad}");
        }
    }

    fn sids(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn a_dacl_is_ours_with_the_system_accounts_and_the_producer_only() {
        let victim = "S-1-5-21-1-2-3-1001";
        let attacker = "S-1-5-21-1-2-3-1002";
        let ours = sids(&["S-1-5-18", "S-1-5-32-544", "S-1-5-19", victim]);
        assert!(dacl_is_ours(&ours, Some(victim)));
        // The attacker's camera claims its own SID for the victim's section.
        assert!(!dacl_is_ours(&ours, Some(attacker)));
        // Without a SID the section is for interactive users.
        assert!(!dacl_is_ours(&ours, None));
        assert!(dacl_is_ours(&sids(&["S-1-5-18", "S-1-5-4"]), None));
        // Anyone else in it, or the producer missing, is not ours.
        assert!(!dacl_is_ours(
            &sids(&["S-1-5-18", victim, "S-1-1-0"]),
            Some(victim)
        ));
        assert!(!dacl_is_ours(
            &sids(&["S-1-5-18", victim, "?"]),
            Some(victim)
        ));
        assert!(!dacl_is_ours(
            &sids(&["S-1-5-18", "S-1-5-19"]),
            Some(victim)
        ));
        assert!(!dacl_is_ours(&[], Some(victim)));
    }

    /// A section in the `Local\` namespace, which needs no privilege and goes away with the process,
    /// so these tests touch nothing on the machine. Nothing is registered and no camera is made.
    fn local_name() -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        format!("Local\\Skakel.Test.{}.{nanos:x}", std::process::id())
    }

    #[test]
    fn opens_an_existing_section_made_for_the_same_producer() {
        let name = local_name();
        let me = crate::sys::current_user_sid().unwrap();
        let (_first, created) = Section::create(&name, 8192, Some(&me)).unwrap();
        assert!(created);
        let (second, created) = Section::create(&name, 8192, Some(&me)).unwrap();
        assert!(!created);
        assert!(second.len() >= 8192);
    }

    #[test]
    fn refuses_an_existing_section_made_for_another_producer() {
        let name = local_name();
        let me = crate::sys::current_user_sid().unwrap();
        let (_first, created) = Section::create(&name, 8192, Some(&me)).unwrap();
        assert!(created);
        // Another user's camera with the same id, naming its own user as the producer.
        let error = Section::create(&name, 8192, Some("S-1-5-21-1-2-3-1002"))
            .err()
            .expect("a section for someone else is not opened");
        assert!(
            matches!(&error, crate::Error::Io(e) if e.kind() == std::io::ErrorKind::PermissionDenied),
            "{error}"
        );
        // And not when the camera names nobody and the section was made for one user.
        assert!(Section::create(&name, 8192, None).is_err());
    }

    #[test]
    fn falls_back_to_interactive_users_for_anything_but_a_sid() {
        assert!(security_descriptor(None).ends_with("(A;;GRGW;;;IU)"));
        assert!(security_descriptor(Some("S-1-1-0)(A;;GA;;;WD")).ends_with("(A;;GRGW;;;IU)"));
    }
}
