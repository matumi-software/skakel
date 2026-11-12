//! The activation object Frame Server gets from the class factory. Frame Server puts the camera's
//! attributes into it, the producer's among them, then asks it for the media source. It is its own
//! attribute store by passing every call to one Media Foundation made, as Microsoft's sample's
//! `VirtualCameraMediaSourceActivate` does.

use std::ffi::c_void;
use std::sync::Mutex;

use windows::Win32::Foundation::E_POINTER;
use windows::Win32::Media::MediaFoundation::{
    IMFActivate, IMFActivate_Impl, IMFAttributes, IMFAttributes_Impl, MF_ATTRIBUTE_TYPE,
    MF_ATTRIBUTES_MATCH_TYPE, MFCreateAttributes, MFT_TRANSFORM_CLSID_Attribute,
};
use windows::Win32::System::Com::StructuredStorage::PROPVARIANT;
use windows::core::{
    BOOL, ComObject, GUID, IUnknown, Interface, PCWSTR, PWSTR, Ref, Result, implement,
};

use skakel_vcam::contract::SOURCE_CLSID;

use crate::source::MediaSource;
use crate::{ObjectCount, log};

#[implement(IMFActivate)]
pub struct Activate {
    store: IMFAttributes,
    source: Mutex<Option<ComObject<MediaSource>>>,
    _count: ObjectCount,
}

impl Activate {
    pub fn new() -> Result<Self> {
        let mut store = None;
        unsafe {
            MFCreateAttributes(&mut store, 8)?;
            let store = store.ok_or(E_POINTER)?;
            store.SetGUID(
                &MFT_TRANSFORM_CLSID_Attribute,
                &GUID::from_u128(SOURCE_CLSID),
            )?;
            Ok(Self {
                store,
                source: Mutex::new(None),
                _count: ObjectCount::new(),
            })
        }
    }
}

impl IMFActivate_Impl for Activate_Impl {
    fn ActivateObject(&self, iid: *const GUID, out: *mut *mut c_void) -> Result<()> {
        crate::guard("ActivateObject", || {
            if out.is_null() || iid.is_null() {
                return Err(E_POINTER.into());
            }
            unsafe { *out = std::ptr::null_mut() };
            let source = MediaSource::create(&self.store)
                .inspect_err(|e| log(&format!("cannot create the media source: {e}")))?;
            let unknown: IUnknown = source.to_interface();
            unsafe { unknown.query(iid, out).ok()? };
            *crate::lock(&self.source) = Some(source);
            Ok(())
        })
    }

    fn ShutdownObject(&self) -> Result<()> {
        crate::guard("ShutdownObject", || {
            if let Some(source) = crate::lock(&self.source).take() {
                let _ = source.shutdown();
            }
            Ok(())
        })
    }

    fn DetachObject(&self) -> Result<()> {
        crate::guard("DetachObject", || {
            crate::lock(&self.source).take();
            Ok(())
        })
    }
}

impl IMFAttributes_Impl for Activate_Impl {
    fn GetItem(&self, key: *const GUID, value: *mut PROPVARIANT) -> Result<()> {
        unsafe { self.store.GetItem(key, (!value.is_null()).then_some(value)) }
    }

    fn GetItemType(&self, key: *const GUID) -> Result<MF_ATTRIBUTE_TYPE> {
        unsafe { self.store.GetItemType(key) }
    }

    fn CompareItem(&self, key: *const GUID, value: *const PROPVARIANT) -> Result<BOOL> {
        unsafe { self.store.CompareItem(key, value) }
    }

    fn Compare(
        &self,
        theirs: Ref<IMFAttributes>,
        match_type: MF_ATTRIBUTES_MATCH_TYPE,
    ) -> Result<BOOL> {
        unsafe { self.store.Compare(theirs.as_ref(), match_type) }
    }

    fn GetUINT32(&self, key: *const GUID) -> Result<u32> {
        unsafe { self.store.GetUINT32(key) }
    }

    fn GetUINT64(&self, key: *const GUID) -> Result<u64> {
        unsafe { self.store.GetUINT64(key) }
    }

    fn GetDouble(&self, key: *const GUID) -> Result<f64> {
        unsafe { self.store.GetDouble(key) }
    }

    fn GetGUID(&self, key: *const GUID) -> Result<GUID> {
        unsafe { self.store.GetGUID(key) }
    }

    fn GetStringLength(&self, key: *const GUID) -> Result<u32> {
        unsafe { self.store.GetStringLength(key) }
    }

    fn GetString(&self, key: *const GUID, value: PWSTR, size: u32, len: *mut u32) -> Result<()> {
        unsafe {
            (Interface::vtable(&self.store).GetString)(self.store.as_raw(), key, value, size, len)
                .ok()
        }
    }

    fn GetAllocatedString(&self, key: *const GUID, value: *mut PWSTR, len: *mut u32) -> Result<()> {
        unsafe { self.store.GetAllocatedString(key, value, len) }
    }

    fn GetBlobSize(&self, key: *const GUID) -> Result<u32> {
        unsafe { self.store.GetBlobSize(key) }
    }

    fn GetBlob(&self, key: *const GUID, buffer: *mut u8, size: u32, len: *mut u32) -> Result<()> {
        unsafe {
            (Interface::vtable(&self.store).GetBlob)(self.store.as_raw(), key, buffer, size, len)
                .ok()
        }
    }

    fn GetAllocatedBlob(
        &self,
        key: *const GUID,
        buffer: *mut *mut u8,
        size: *mut u32,
    ) -> Result<()> {
        unsafe { self.store.GetAllocatedBlob(key, buffer, size) }
    }

    fn GetUnknown(&self, key: *const GUID, iid: *const GUID, out: *mut *mut c_void) -> Result<()> {
        unsafe {
            (Interface::vtable(&self.store).GetUnknown)(self.store.as_raw(), key, iid, out).ok()
        }
    }

    fn SetItem(&self, key: *const GUID, value: *const PROPVARIANT) -> Result<()> {
        unsafe { self.store.SetItem(key, value) }
    }

    fn DeleteItem(&self, key: *const GUID) -> Result<()> {
        unsafe { self.store.DeleteItem(key) }
    }

    fn DeleteAllItems(&self) -> Result<()> {
        unsafe { self.store.DeleteAllItems() }
    }

    fn SetUINT32(&self, key: *const GUID, value: u32) -> Result<()> {
        unsafe { self.store.SetUINT32(key, value) }
    }

    fn SetUINT64(&self, key: *const GUID, value: u64) -> Result<()> {
        unsafe { self.store.SetUINT64(key, value) }
    }

    fn SetDouble(&self, key: *const GUID, value: f64) -> Result<()> {
        unsafe { self.store.SetDouble(key, value) }
    }

    fn SetGUID(&self, key: *const GUID, value: *const GUID) -> Result<()> {
        unsafe { self.store.SetGUID(key, value) }
    }

    fn SetString(&self, key: *const GUID, value: &PCWSTR) -> Result<()> {
        unsafe { self.store.SetString(key, *value) }
    }

    fn SetBlob(&self, key: *const GUID, buffer: *const u8, size: u32) -> Result<()> {
        unsafe {
            (Interface::vtable(&self.store).SetBlob)(self.store.as_raw(), key, buffer, size).ok()
        }
    }

    fn SetUnknown(&self, key: *const GUID, value: Ref<IUnknown>) -> Result<()> {
        unsafe { self.store.SetUnknown(key, value.as_ref()) }
    }

    fn LockStore(&self) -> Result<()> {
        unsafe { self.store.LockStore() }
    }

    fn UnlockStore(&self) -> Result<()> {
        unsafe { self.store.UnlockStore() }
    }

    fn GetCount(&self) -> Result<u32> {
        unsafe { self.store.GetCount() }
    }

    fn GetItemByIndex(&self, index: u32, key: *mut GUID, value: *mut PROPVARIANT) -> Result<()> {
        unsafe {
            self.store
                .GetItemByIndex(index, key, (!value.is_null()).then_some(value))
        }
    }

    fn CopyAllItems(&self, destination: Ref<IMFAttributes>) -> Result<()> {
        unsafe { self.store.CopyAllItems(destination.as_ref()) }
    }
}
