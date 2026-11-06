//! The video stream and its pacing.
//!
//! The samples answer `RequestSample` on a clock of their own: a thread wakes once a frame, at the
//! camera's rate, and answers the oldest waiting request with whatever picture is due, stamped with
//! that slot's time. A producer that falls behind or stops changes what is sent, never when.
//! Microsoft's sample and VCamSample answer each request at once, stamped with the time of the
//! request; VCamSample reports Teams sending nothing to the other side of a call that way.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use windows::Win32::Foundation::{E_POINTER, E_UNEXPECTED, HANDLE, S_OK, WAIT_OBJECT_0};
use windows::Win32::Media::KernelStreaming::PINNAME_VIDEO_CAPTURE;
use windows::Win32::Media::MediaFoundation::*;
use windows::Win32::System::Com::StructuredStorage::PROPVARIANT;
use windows::Win32::System::Threading::{
    CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, CreateEventW, CreateWaitableTimerExW, INFINITE,
    SetEvent, SetWaitableTimer, TIMER_ALL_ACCESS, WaitForMultipleObjects, WaitForSingleObject,
};
use windows::core::{
    ComObject, GUID, HRESULT, IUnknown, Interface, PCWSTR, Ref, Result, implement,
};

use skakel_vcam::layout::Format;
use skakel_vcam::pacing::{Pacer, Tick};

use crate::config::Config;
use crate::frames::{Frames, copy_nv12_pitched};
use crate::{ObjectCount, log};

/// Samples the allocator keeps, as both samples use.
const SAMPLES: u32 = 10;
/// Requests waiting beyond this are refused; Frame Server keeps far fewer outstanding.
const MAX_PENDING: usize = 64;

const NO_GUID: GUID = GUID::zeroed();

struct Inner {
    shutdown: bool,
    state: MF_STREAM_STATE,
    queue: Option<IMFMediaEventQueue>,
    source: Option<IMFMediaSource>,
    allocator: Option<IMFVideoSampleAllocator>,
    allocator_ready: bool,
    media_type: Option<IMFMediaType>,
    pending: VecDeque<Option<IUnknown>>,
    frames: Option<Frames>,
    config: Config,
}

// Media Foundation's event queue, allocator, samples and the tokens Frame Server passes are free
// threaded, and every use of them is under the mutex.
unsafe impl Send for Inner {}

struct Shared {
    inner: Mutex<Inner>,
}

/// The pacing thread and the event that stops it.
struct Pacing {
    stop: SendHandle,
    _timer: SendHandle,
    thread: JoinHandle<()>,
}

/// A kernel handle; handles may be used from any thread.
struct SendHandle(HANDLE);
unsafe impl Send for SendHandle {}

impl Drop for SendHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[implement(IMFMediaStream2)]
pub struct MediaStream {
    shared: Arc<Shared>,
    pacing: Mutex<Option<Pacing>>,
    descriptor: IMFStreamDescriptor,
    attributes: IMFAttributes,
    _count: ObjectCount,
}

/// The one media type the stream offers: NV12 at the camera's size and rate, BT.601 limited range.
fn media_type(format: &Format) -> Result<IMFMediaType> {
    let pair = |a: u32, b: u32| (u64::from(a) << 32) | u64::from(b);
    let frame_size = format.frame_size() as u32;
    let bitrate = (u64::from(frame_size) * 8 * u64::from(format.fps_num)
        / u64::from(format.fps_den))
    .min(u64::from(u32::MAX)) as u32;
    unsafe {
        let media_type = MFCreateMediaType()?;
        media_type.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
        media_type.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_NV12)?;
        media_type.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
        media_type.SetUINT32(&MF_MT_ALL_SAMPLES_INDEPENDENT, 1)?;
        media_type.SetUINT64(&MF_MT_FRAME_SIZE, pair(format.width, format.height))?;
        media_type.SetUINT64(&MF_MT_FRAME_RATE, pair(format.fps_num, format.fps_den))?;
        media_type.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, pair(1, 1))?;
        media_type.SetUINT32(&MF_MT_DEFAULT_STRIDE, format.width)?;
        media_type.SetUINT32(&MF_MT_FIXED_SIZE_SAMPLES, 1)?;
        media_type.SetUINT32(&MF_MT_SAMPLE_SIZE, frame_size)?;
        media_type.SetUINT32(&MF_MT_AVG_BITRATE, bitrate)?;
        media_type.SetUINT32(&MF_MT_YUV_MATRIX, MFVideoTransferMatrix_BT601.0 as u32)?;
        media_type.SetUINT32(&MF_MT_VIDEO_NOMINAL_RANGE, MFNominalRange_16_235.0 as u32)?;
        Ok(media_type)
    }
}

/// What Frame Server reads to know this is a shared colour capture stream.
fn set_stream_attributes(store: &IMFAttributes) -> Result<()> {
    unsafe {
        store.SetGUID(&MF_DEVICESTREAM_STREAM_CATEGORY, &PINNAME_VIDEO_CAPTURE)?;
        store.SetUINT32(&MF_DEVICESTREAM_STREAM_ID, 0)?;
        store.SetUINT32(&MF_DEVICESTREAM_FRAMESERVER_SHARED, 1)?;
        store.SetUINT32(
            &MF_DEVICESTREAM_ATTRIBUTE_FRAMESOURCE_TYPES,
            MFFrameSourceTypes_Color.0 as u32,
        )
    }
}

impl MediaStream {
    pub fn create(source: IMFMediaSource, config: Config) -> Result<ComObject<MediaStream>> {
        unsafe {
            let media_type = media_type(&config.format)?;
            let descriptor = MFCreateStreamDescriptor(0, &[Some(media_type.clone())])?;
            descriptor
                .GetMediaTypeHandler()?
                .SetCurrentMediaType(&media_type)?;
            set_stream_attributes(&descriptor)?;
            let mut attributes = None;
            MFCreateAttributes(&mut attributes, 4)?;
            let attributes = attributes.ok_or(E_POINTER)?;
            set_stream_attributes(&attributes)?;
            let inner = Inner {
                shutdown: false,
                state: MF_STREAM_STATE_STOPPED,
                queue: Some(MFCreateEventQueue()?),
                source: Some(source),
                allocator: None,
                allocator_ready: false,
                media_type: Some(media_type),
                pending: VecDeque::new(),
                frames: None,
                config,
            };
            Ok(ComObject::new(MediaStream {
                shared: Arc::new(Shared {
                    inner: Mutex::new(inner),
                }),
                pacing: Mutex::new(None),
                descriptor,
                attributes,
                _count: ObjectCount::new(),
            }))
        }
    }

    pub fn descriptor(&self) -> IMFStreamDescriptor {
        self.descriptor.clone()
    }

    pub fn attributes(&self) -> IMFAttributes {
        self.attributes.clone()
    }

    pub fn set_allocator(&self, allocator: IMFVideoSampleAllocator) -> Result<()> {
        let mut inner = self.live()?;
        if inner.state == MF_STREAM_STATE_RUNNING {
            return Err(MF_E_INVALIDREQUEST.into());
        }
        inner.allocator = Some(allocator);
        inner.allocator_ready = false;
        Ok(())
    }

    /// The source selected the stream with this media type.
    pub fn start(&self, media_type: &IMFMediaType) -> Result<()> {
        let mut inner = self.live()?;
        Self::start_inner(&mut inner, true, Some(media_type))?;
        drop(inner);
        self.start_pacing()
    }

    /// The source deselected the stream or stopped.
    pub fn stop(&self, send_event: bool) -> Result<()> {
        let mut inner = self.live()?;
        Self::stop_inner(&mut inner, send_event)?;
        drop(inner);
        self.stop_pacing();
        Ok(())
    }

    pub fn shutdown(&self) {
        {
            let mut inner = self.shared.inner.lock().unwrap();
            inner.shutdown = true;
            inner.state = MF_STREAM_STATE_STOPPED;
            if let Some(queue) = inner.queue.take() {
                let _ = unsafe { queue.Shutdown() };
            }
            inner.pending.clear();
            inner.source = None;
            inner.frames = None;
            if let Some(allocator) = inner.allocator.take()
                && inner.allocator_ready
            {
                let _ = unsafe { allocator.UninitializeSampleAllocator() };
            }
        }
        self.stop_pacing();
    }

    fn live(&self) -> Result<std::sync::MutexGuard<'_, Inner>> {
        let inner = self.shared.inner.lock().unwrap();
        if inner.shutdown {
            Err(MF_E_SHUTDOWN.into())
        } else {
            Ok(inner)
        }
    }

    fn queue(&self) -> Result<IMFMediaEventQueue> {
        self.live()?.queue.clone().ok_or(E_UNEXPECTED.into())
    }

    fn start_inner(
        inner: &mut Inner,
        send_event: bool,
        new_type: Option<&IMFMediaType>,
    ) -> Result<()> {
        unsafe {
            let mut changed = false;
            if let Some(new_type) = new_type {
                changed = match &inner.media_type {
                    Some(current) => !current
                        .Compare(new_type, MF_ATTRIBUTES_MATCH_ALL_ITEMS)?
                        .as_bool(),
                    None => true,
                };
                if changed {
                    inner.media_type = Some(new_type.clone());
                }
            }
            if inner.state != MF_STREAM_STATE_RUNNING || changed || !inner.allocator_ready {
                let media_type = inner.media_type.clone().ok_or(E_UNEXPECTED)?;
                let allocator = match &inner.allocator {
                    Some(allocator) => allocator.clone(),
                    // Loaded outside Frame Server, nobody provides one.
                    None => {
                        let mut raw = std::ptr::null_mut();
                        MFCreateVideoSampleAllocatorEx(&IMFVideoSampleAllocator::IID, &mut raw)?;
                        let allocator = IMFVideoSampleAllocator::from_raw(raw);
                        inner.allocator = Some(allocator.clone());
                        allocator
                    }
                };
                if inner.allocator_ready {
                    let _ = allocator.UninitializeSampleAllocator();
                }
                allocator.InitializeSampleAllocator(SAMPLES, &media_type)?;
                inner.allocator_ready = true;
                if inner.frames.is_none() {
                    inner.frames = Some(Frames::new(inner.config.clone()));
                }
            }
            if send_event {
                inner
                    .queue
                    .as_ref()
                    .ok_or(E_UNEXPECTED)?
                    .QueueEventParamVar(
                        MEStreamStarted.0 as u32,
                        &NO_GUID,
                        S_OK,
                        std::ptr::null(),
                    )?;
            }
            inner.state = MF_STREAM_STATE_RUNNING;
            Ok(())
        }
    }

    fn stop_inner(inner: &mut Inner, send_event: bool) -> Result<()> {
        inner.state = MF_STREAM_STATE_STOPPED;
        inner.pending.clear();
        inner.frames = None;
        if inner.allocator_ready {
            if let Some(allocator) = &inner.allocator {
                let _ = unsafe { allocator.UninitializeSampleAllocator() };
            }
            inner.allocator_ready = false;
        }
        if send_event {
            unsafe {
                inner
                    .queue
                    .as_ref()
                    .ok_or(E_UNEXPECTED)?
                    .QueueEventParamVar(
                        MEStreamStopped.0 as u32,
                        &NO_GUID,
                        S_OK,
                        std::ptr::null(),
                    )?
            };
        }
        Ok(())
    }

    fn start_pacing(&self) -> Result<()> {
        let mut pacing = self.pacing.lock().unwrap();
        if pacing.as_ref().is_some_and(|p| !p.thread.is_finished()) {
            return Ok(());
        }
        let format = self.shared.inner.lock().unwrap().config.format;
        unsafe {
            let stop = SendHandle(CreateEventW(None, true, false, PCWSTR::null())?);
            let timer = SendHandle(CreateWaitableTimerExW(
                None,
                PCWSTR::null(),
                CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
                TIMER_ALL_ACCESS.0,
            )?);
            let (stop_raw, timer_raw) = (stop.0.0 as usize, timer.0.0 as usize);
            let shared = self.shared.clone();
            let thread = std::thread::Builder::new()
                .name("skakel-vcam pacing".into())
                .spawn(move || {
                    run_pacing(
                        &shared,
                        HANDLE(stop_raw as *mut _),
                        HANDLE(timer_raw as *mut _),
                        format,
                    )
                })
                .map_err(|_| windows::core::Error::from(E_UNEXPECTED))?;
            *pacing = Some(Pacing {
                stop,
                _timer: timer,
                thread,
            });
        }
        Ok(())
    }

    fn stop_pacing(&self) {
        // Taken out first: the thread may be waiting for the stream's lock, never for this one.
        let Some(pacing) = self.pacing.lock().unwrap().take() else {
            return;
        };
        unsafe {
            let _ = SetEvent(pacing.stop.0);
        }
        let _ = pacing.thread.join();
    }
}

impl Drop for MediaStream {
    fn drop(&mut self) {
        self.stop_pacing();
    }
}

/// Wakes at each slot on the grid until `stop` is set.
fn run_pacing(shared: &Shared, stop: HANDLE, timer: HANDLE, format: Format) {
    let mut pacer = Pacer::new(unsafe { MFGetSystemTime() }, format.fps_num, format.fps_den);
    loop {
        let wait = pacer.next_due() - unsafe { MFGetSystemTime() };
        let stopped = unsafe {
            if wait > 0 {
                // Negative: relative, in 100 ns units.
                let due = -wait;
                if SetWaitableTimer(timer, &due, 0, None, None, false).is_err() {
                    log("cannot set the pacing timer");
                    return;
                }
                WaitForMultipleObjects(&[stop, timer], false, INFINITE) == WAIT_OBJECT_0
            } else {
                WaitForSingleObject(stop, 0) == WAIT_OBJECT_0
            }
        };
        if stopped {
            return;
        }
        if let Some(tick) = pacer.poll(unsafe { MFGetSystemTime() })
            && let Err(e) = shared.tick(tick)
        {
            log(&format!("frame {} not sent: {e}", tick.index));
        }
    }
}

impl Shared {
    /// One slot on the grid: take in the producer's latest, and answer the oldest request.
    fn tick(&self, tick: Tick) -> Result<()> {
        let mut guard = self.inner.lock().unwrap();
        let inner = &mut *guard;
        if inner.shutdown || inner.state != MF_STREAM_STATE_RUNNING {
            return Ok(());
        }
        let format = inner.config.format;
        let Some(frames) = inner.frames.as_mut() else {
            return Ok(());
        };
        // Always, so the source knows how fresh the producer's frame is even when nobody asks.
        let picture = frames.select((tick.time / 10_000) as u64);
        if inner.pending.is_empty() {
            return Ok(());
        }
        let (Some(allocator), Some(queue)) = (&inner.allocator, &inner.queue) else {
            return Ok(());
        };
        unsafe {
            let sample = match allocator.AllocateSample() {
                Ok(sample) => sample,
                // Every sample is still downstream: skip this slot, the request waits for the next.
                Err(e) if e.code() == MF_E_SAMPLEALLOCATOR_EMPTY => return Ok(()),
                Err(e) => return Err(e),
            };
            fill(&sample, picture, &format)?;
            sample.SetSampleTime(tick.time)?;
            sample.SetSampleDuration(tick.duration)?;
            if let Some(token) = inner.pending.pop_front().flatten() {
                sample.SetUnknown(&MFSampleExtension_Token, &token)?;
            }
            queue.QueueEventParamUnk(MEMediaSample.0 as u32, &NO_GUID, S_OK, &sample)
        }
    }
}

/// Copies `picture` into the sample's buffer, minding the buffer's row pitch.
unsafe fn fill(sample: &IMFSample, picture: &[u8], format: &Format) -> Result<()> {
    let (width, height) = (format.width as usize, format.height as usize);
    unsafe {
        let buffer = sample.GetBufferByIndex(0)?;
        if let Ok(buffer) = buffer.cast::<IMF2DBuffer2>() {
            let (mut scan0, mut pitch, mut start, mut len) =
                (std::ptr::null_mut(), 0i32, std::ptr::null_mut(), 0u32);
            buffer.Lock2DSize(
                MF2DBuffer_LockFlags_Write,
                &mut scan0,
                &mut pitch,
                &mut start,
                &mut len,
            )?;
            let pitch = pitch as usize;
            let available = (len as usize).saturating_sub(scan0 as usize - start as usize);
            let needed =
                (pitch * (height + height / 2)).saturating_sub(pitch.saturating_sub(width));
            let result = if pitch >= width && available >= needed {
                copy_nv12_pitched(
                    picture,
                    width,
                    height,
                    std::slice::from_raw_parts_mut(scan0, available),
                    pitch,
                );
                Ok(())
            } else {
                Err(E_UNEXPECTED.into())
            };
            buffer.Unlock2D()?;
            result
        } else {
            let (mut data, mut max) = (std::ptr::null_mut(), 0u32);
            buffer.Lock(&mut data, Some(&mut max), None)?;
            let result: Result<()> = if max as usize >= picture.len() {
                std::ptr::copy_nonoverlapping(picture.as_ptr(), data, picture.len());
                Ok(())
            } else {
                Err(E_UNEXPECTED.into())
            };
            buffer.Unlock()?;
            result?;
            buffer.SetCurrentLength(picture.len() as u32)
        }
    }
}

impl IMFMediaEventGenerator_Impl for MediaStream_Impl {
    fn GetEvent(&self, flags: MEDIA_EVENT_GENERATOR_GET_EVENT_FLAGS) -> Result<IMFMediaEvent> {
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

impl IMFMediaStream_Impl for MediaStream_Impl {
    fn GetMediaSource(&self) -> Result<IMFMediaSource> {
        self.live()?.source.clone().ok_or(MF_E_SHUTDOWN.into())
    }

    fn GetStreamDescriptor(&self) -> Result<IMFStreamDescriptor> {
        drop(self.live()?);
        Ok(self.descriptor.clone())
    }

    fn RequestSample(&self, token: Ref<IUnknown>) -> Result<()> {
        let mut inner = self.live()?;
        if inner.state != MF_STREAM_STATE_RUNNING || inner.pending.len() >= MAX_PENDING {
            return Err(MF_E_INVALIDREQUEST.into());
        }
        inner.pending.push_back(token.cloned());
        Ok(())
    }
}

impl IMFMediaStream2_Impl for MediaStream_Impl {
    fn SetStreamState(&self, state: MF_STREAM_STATE) -> Result<()> {
        let mut inner = self.live()?;
        if inner.state == state {
            return Ok(());
        }
        match state {
            MF_STREAM_STATE_PAUSED if inner.state == MF_STREAM_STATE_RUNNING => {
                inner.state = MF_STREAM_STATE_PAUSED;
                Ok(())
            }
            MF_STREAM_STATE_RUNNING => {
                MediaStream::start_inner(&mut inner, false, None)?;
                drop(inner);
                self.start_pacing()
            }
            MF_STREAM_STATE_STOPPED => {
                MediaStream::stop_inner(&mut inner, false)?;
                drop(inner);
                self.stop_pacing();
                Ok(())
            }
            _ => Err(MF_E_INVALID_STATE_TRANSITION.into()),
        }
    }

    fn GetStreamState(&self) -> Result<MF_STREAM_STATE> {
        Ok(self.live()?.state)
    }
}
