//! The class factory COM asks for in `DllGetClassObject`. It makes the activation object, as both
//! samples do.

use std::ffi::c_void;

use windows::Win32::Foundation::{CLASS_E_NOAGGREGATION, E_POINTER};
use windows::Win32::System::Com::{IClassFactory, IClassFactory_Impl};
use windows::core::{BOOL, GUID, IUnknown, Interface, Ref, Result, implement};

use crate::ObjectCount;
use crate::activate::Activate;

#[implement(IClassFactory)]
pub struct ClassFactory {
    _count: ObjectCount,
}

impl ClassFactory {
    pub fn new() -> Self {
        Self {
            _count: ObjectCount::new(),
        }
    }
}

impl IClassFactory_Impl for ClassFactory_Impl {
    fn CreateInstance(
        &self,
        outer: Ref<IUnknown>,
        iid: *const GUID,
        out: *mut *mut c_void,
    ) -> Result<()> {
        if out.is_null() || iid.is_null() {
            return Err(E_POINTER.into());
        }
        unsafe { *out = std::ptr::null_mut() };
        if !outer.is_null() {
            return Err(CLASS_E_NOAGGREGATION.into());
        }
        let activate: IUnknown = Activate::new()?.into();
        unsafe { activate.query(iid, out).ok() }
    }

    fn LockServer(&self, lock: BOOL) -> Result<()> {
        crate::lock_server(lock.as_bool());
        Ok(())
    }
}
