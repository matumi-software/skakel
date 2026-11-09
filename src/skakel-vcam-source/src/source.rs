//! The media source: one video stream, NV12 at the camera's size and rate. Its state handling
//! follows `SimpleMediaSource` in Microsoft's sample.

use std::ffi::c_void;
use std::sync::Mutex;

use windows::Win32::Foundation::{
    E_INVALIDARG, E_NOTIMPL, E_POINTER, E_UNEXPECTED, ERROR_SET_NOT_FOUND, S_OK,
};
use windows::Win32::Media::KernelStreaming::{
    IKsControl, IKsControl_Impl, KSCAMERAPROFILE_Legacy, KSIDENTIFIER,
};
use windows::Win32::Media::MediaFoundation::*;
use windows::Win32::System::Com::StructuredStorage::PROPVARIANT;
use windows::core::{BOOL, ComObject, GUID, HRESULT, IUnknown, Interface, Ref, Result, implement};

use crate::config::Config;
use crate::stream::MediaStream;
use crate::{ObjectCount, log};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Stopped,
    Started,
    Shutdown,
}

struct Inner {
    state: State,
    queue: Option<IMFMediaEventQueue>,
    descriptor: Option<IMFPresentationDescriptor>,
    attributes: Option<IMFAttributes>,
    stream: Option<ComObject<MediaStream>>,
}

#[implement(IMFMediaSourceEx, IMFGetService, IKsControl, IMFSampleAllocatorControl)]
pub struct MediaSource {
    inner: Mutex<Inner>,
    _count: ObjectCount,
}

/// The GUID Media Foundation calls GUID_NULL.
const NO_GUID: GUID = GUID::zeroed();

fn not_found() -> windows::core::Error {
    HRESULT::from_win32(ERROR_SET_NOT_FOUND.0).into()
}

impl MediaSource {
    /// A source for the camera the activation attributes describe.
    pub fn create(activate_attributes: &IMFAttributes) -> Result<ComObject<MediaSource>> {
        let config = Config::from_attributes(activate_attributes);
        let format = config.format;
        log(&format!(
            "source for camera {:?}, {}x{} at {}/{}",
            config.camera_id, format.width, format.height, format.fps_num, format.fps_den
        ));
        unsafe {
            let mut attributes = None;
            MFCreateAttributes(&mut attributes, 4)?;
            let attributes = attributes.ok_or(E_POINTER)?;
            activate_attributes.CopyAllItems(&attributes)?;
            // The legacy profile is required, so apps that know nothing of profiles still find the
            // stream. The sample's filter `FRT<=30,1` would hide a 60 fps camera; ours allows its rate.
            let profiles = MFCreateSensorProfileCollection()?;
            let profile = MFCreateSensorProfile(&KSCAMERAPROFILE_Legacy, 0, None)?;
            let filter = windows::core::HSTRING::from(format!(
                "((RES==;FRT<={},{};SUT==))",
                format.fps_num, format.fps_den
            ));
            profile.AddProfileFilter(0, &filter)?;
            profiles.AddProfile(&profile)?;
            attributes.SetUnknown(&MF_DEVICEMFT_SENSORPROFILE_COLLECTION, &profiles)?;

            let source = ComObject::new(MediaSource {
                inner: Mutex::new(Inner {
                    state: State::Stopped,
                    queue: Some(MFCreateEventQueue()?),
                    descriptor: None,
                    attributes: Some(attributes),
                    stream: None,
                }),
                _count: ObjectCount::new(),
            });
            let stream = MediaStream::create(source.cast::<IMFMediaSource>()?, config)?;
            let descriptor = MFCreatePresentationDescriptor(Some(&[Some(stream.descriptor())]))?;
            let mut inner = source.inner.lock().unwrap();
            inner.descriptor = Some(descriptor);
            inner.stream = Some(stream);
            drop(inner);
            Ok(source)
        }
    }

    /// Shuts the source down: what `IMFMediaSource::Shutdown` does.
    pub fn shutdown(&self) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.state = State::Shutdown;
        if let Some(queue) = inner.queue.take() {
            let _ = unsafe { queue.Shutdown() };
        }
        inner.descriptor = None;
        inner.attributes = None;
        let stream = inner.stream.take();
        drop(inner);
        if let Some(stream) = stream {
            stream.shutdown();
        }
        Ok(())
    }

    fn live(&self) -> Result<std::sync::MutexGuard<'_, Inner>> {
        let inner = self.inner.lock().unwrap();
        match inner.state {
            State::Shutdown => Err(MF_E_SHUTDOWN.into()),
            _ if inner.queue.is_none() || inner.stream.is_none() => Err(E_UNEXPECTED.into()),
            _ => Ok(inner),
        }
    }

    fn queue(&self) -> Result<IMFMediaEventQueue> {
        Ok(self.live()?.queue.clone().unwrap())
    }
}

impl IMFMediaEventGenerator_Impl for MediaSource_Impl {
    fn GetEvent(&self, flags: MEDIA_EVENT_GENERATOR_GET_EVENT_FLAGS) -> Result<IMFMediaEvent> {
        // GetEvent may block, so the lock is not held for it.
        let queue = self.queue()?;
        unsafe { queue.GetEvent(flags.0) }
    }

    fn BeginGetEvent(&self, callback: Ref<IMFAsyncCallback>, state: Ref<IUnknown>) -> Result<()> {
        unsafe {
            self.queue()?
                .BeginGetEvent(callback.as_ref(), state.as_ref())
        }
    }

    fn EndGetEvent(&self, result: Ref<IMFAsyncResult>) -> Result<IMFMediaEvent> {
        unsafe { self.queue()?.EndGetEvent(result.as_ref()) }
    }

    fn QueueEvent(
        &self,
        event: u32,
        extended: *const GUID,
        status: HRESULT,
        value: *const PROPVARIANT,
    ) -> Result<()> {
        unsafe {
            self.queue()?
                .QueueEventParamVar(event, extended, status, value)
        }
    }
}

impl IMFMediaSource_Impl for MediaSource_Impl {
    fn GetCharacteristics(&self) -> Result<u32> {
        drop(self.live()?);
        Ok(MFMEDIASOURCE_IS_LIVE.0 as u32)
    }

    fn CreatePresentationDescriptor(&self) -> Result<IMFPresentationDescriptor> {
        let inner = self.live()?;
        unsafe { inner.descriptor.as_ref().ok_or(E_UNEXPECTED)?.Clone() }
    }

    fn Start(
        &self,
        descriptor: Ref<IMFPresentationDescriptor>,
        time_format: *const GUID,
        _start: *const PROPVARIANT,
    ) -> Result<()> {
        let mut inner = self.live()?;
        let requested = descriptor
            .ok()
            .map_err(|_| windows::core::Error::from(E_INVALIDARG))?;
        if !time_format.is_null() && unsafe { *time_format } != NO_GUID {
            return Err(MF_E_UNSUPPORTED_TIME_FORMAT.into());
        }
        unsafe {
            if requested.GetStreamDescriptorCount()? != 1 {
                return Err(E_INVALIDARG.into());
            }
            let mut selected = BOOL::default();
            let mut requested_stream = None;
            requested.GetStreamDescriptorByIndex(0, &mut selected, &mut requested_stream)?;
            let requested_stream = requested_stream.ok_or(E_INVALIDARG)?;
            if requested_stream.GetStreamIdentifier()? != 0 {
                return Err(MF_E_NOT_FOUND.into());
            }
            let ours = inner.descriptor.clone().ok_or(E_UNEXPECTED)?;
            let mut was_selected = BOOL::default();
            let mut ours_stream = None;
            ours.GetStreamDescriptorByIndex(0, &mut was_selected, &mut ours_stream)?;

            let queue = inner.queue.clone().unwrap();
            let stream = inner.stream.clone().unwrap();
            if selected.as_bool() {
                ours.SelectStream(0)?;
                let media_type = requested_stream
                    .GetMediaTypeHandler()?
                    .GetCurrentMediaType()?;
                let event = if was_selected.as_bool() {
                    MEUpdatedStream
                } else {
                    MENewStream
                };
                queue.QueueEventParamUnk(
                    event.0 as u32,
                    &NO_GUID,
                    S_OK,
                    &stream.to_interface::<IUnknown>(),
                )?;
                stream.start(&media_type)?;
            } else if was_selected.as_bool() {
                ours.DeselectStream(0)?;
                stream.stop(false)?;
            }
            let now = PROPVARIANT::from(MFGetSystemTime());
            queue.QueueEventParamVar(MESourceStarted.0 as u32, &NO_GUID, S_OK, &now)?;
            inner.state = State::Started;
        }
        Ok(())
    }

    fn Stop(&self) -> Result<()> {
        let mut inner = self.live()?;
        if inner.state != State::Started {
            return Err(MF_E_INVALID_STATE_TRANSITION.into());
        }
        inner.state = State::Stopped;
        unsafe {
            inner.stream.clone().unwrap().stop(true)?;
            inner
                .descriptor
                .as_ref()
                .ok_or(E_UNEXPECTED)?
                .DeselectStream(0)?;
            let now = PROPVARIANT::from(MFGetSystemTime());
            inner.queue.as_ref().unwrap().QueueEventParamVar(
                MESourceStopped.0 as u32,
                &NO_GUID,
                S_OK,
                &now,
            )
        }
    }

    fn Pause(&self) -> Result<()> {
        // A live camera does not pause.
        Err(MF_E_INVALID_STATE_TRANSITION.into())
    }

    fn Shutdown(&self) -> Result<()> {
        self.shutdown()
    }
}

impl IMFMediaSourceEx_Impl for MediaSource_Impl {
    fn GetSourceAttributes(&self) -> Result<IMFAttributes> {
        // The store itself, not a copy: components upstream write to it and expect it to stay.
        self.live()?.attributes.clone().ok_or(E_UNEXPECTED.into())
    }

    fn GetStreamAttributes(&self, stream_id: u32) -> Result<IMFAttributes> {
        let inner = self.live()?;
        if stream_id != 0 {
            return Err(MF_E_NOT_FOUND.into());
        }
        Ok(inner.stream.as_ref().unwrap().attributes())
    }

    fn SetD3DManager(&self, _manager: Ref<IUnknown>) -> Result<()> {
        // Frames are in system memory; Frame Server ignores the answer.
        Err(E_NOTIMPL.into())
    }
}

impl IMFGetService_Impl for MediaSource_Impl {
    fn GetService(
        &self,
        _service: *const GUID,
        _iid: *const GUID,
        out: *mut *mut c_void,
    ) -> Result<()> {
        if !out.is_null() {
            unsafe { *out = std::ptr::null_mut() };
        }
        Err(MF_E_UNSUPPORTED_SERVICE.into())
    }
}

impl IMFSampleAllocatorControl_Impl for MediaSource_Impl {
    fn SetDefaultAllocator(&self, stream_id: u32, allocator: Ref<IUnknown>) -> Result<()> {
        let inner = self.live()?;
        if stream_id != 0 {
            return Err(MF_E_NOT_FOUND.into());
        }
        let allocator: IMFVideoSampleAllocator = allocator.ok()?.cast()?;
        inner.stream.as_ref().unwrap().set_allocator(allocator)
    }

    fn GetAllocatorUsage(
        &self,
        stream_id: u32,
        input_stream_id: *mut u32,
        usage: *mut MFSampleAllocatorUsage,
    ) -> Result<()> {
        drop(self.live()?);
        if input_stream_id.is_null() || usage.is_null() {
            return Err(E_POINTER.into());
        }
        if stream_id != 0 {
            return Err(MF_E_NOT_FOUND.into());
        }
        unsafe {
            *input_stream_id = stream_id;
            *usage = MFSampleAllocatorUsage_UsesProvidedAllocator;
        }
        Ok(())
    }
}

/// No camera controls. ERROR_SET_NOT_FOUND is what a driver without a handler answers, and what
/// Frame Server expects for a set the camera does not have.
impl IKsControl_Impl for MediaSource_Impl {
    fn KsProperty(
        &self,
        property: *const KSIDENTIFIER,
        length: u32,
        _data: *mut c_void,
        _data_length: u32,
        _returned: *mut u32,
    ) -> Result<()> {
        if property.is_null() || (length as usize) < size_of::<KSIDENTIFIER>() {
            return Err(E_INVALIDARG.into());
        }
        Err(not_found())
    }

    fn KsMethod(
        &self,
        _method: *const KSIDENTIFIER,
        _length: u32,
        _data: *mut c_void,
        _data_length: u32,
        _returned: *mut u32,
    ) -> Result<()> {
        Err(not_found())
    }

    fn KsEvent(
        &self,
        _event: *const KSIDENTIFIER,
        _length: u32,
        _data: *mut c_void,
        _data_length: u32,
        _returned: *mut u32,
    ) -> Result<()> {
        Err(not_found())
    }
}
