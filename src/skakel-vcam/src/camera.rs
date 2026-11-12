//! The producer: create or remove the camera, push frames, set the idle frame.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use windows::Win32::Media::MediaFoundation::{
    IMFVirtualCamera, MFVirtualCameraAccess_CurrentUser, MFVirtualCameraLifetime_System,
};
use windows::core::{GUID, HSTRING};

use crate::contract::{self, attributes};
use crate::convert::{PixelFormat, SizeMismatch, to_nv12};
use crate::layout::{self, Format, FrameWriter};
use crate::section::Section;
use crate::sys::{self, MediaFoundation};
use crate::{Error, Result};

/// How often a producer that has no shared memory yet looks for it again.
const RETRY_INTERVAL: Duration = Duration::from_millis(250);

/// What a camera is: its name, size and rate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CameraOptions {
    /// The name apps list. Windows adds "Windows Virtual Camera" to it in some places.
    pub friendly_name: String,
    pub width: u32,
    pub height: u32,
    /// Frames a second, 1 to 120.
    pub fps: u32,
    /// How long the camera repeats the last frame before it shows the idle frame, 100 ms to 60 s.
    pub idle_timeout: Duration,
}

impl CameraOptions {
    /// A camera of this name, size and rate, with the default 2 second idle timeout.
    pub fn new(friendly_name: impl Into<String>, width: u32, height: u32, fps: u32) -> Self {
        Self {
            friendly_name: friendly_name.into(),
            width,
            height,
            fps,
            idle_timeout: Duration::from_millis(layout::DEFAULT_IDLE_TIMEOUT_MS.into()),
        }
    }

    fn format(&self) -> Result<Format> {
        Ok(Format::new(self.width, self.height, self.fps, 1)?)
    }

    fn validate(&self) -> Result<Format> {
        if self.friendly_name.trim().is_empty() || self.friendly_name.chars().count() > 128 {
            return Err(Error::InvalidArgument(
                "the camera's name must be 1 to 128 characters".into(),
            ));
        }
        self.format()
    }
}

struct Link {
    writer: FrameWriter,
    _section: Section,
}

/// A virtual camera this app feeds. Creating it registers the camera with Windows for the current
/// user, where it stays, also across restarts, until it is removed. While no app writes to it, it
/// shows the idle frame.
///
/// Frames reach the camera only while some app has it open: before that, `push_frame` returns
/// `Ok(false)` and the frame is dropped.
pub struct VirtualCamera {
    options: CameraOptions,
    format: Format,
    id: String,
    link: Option<Link>,
    next_attempt: Instant,
    idle: Option<Vec<u8>>,
}

impl VirtualCamera {
    /// True on Windows 11, where the virtual camera exists.
    pub fn is_supported() -> bool {
        sys::check_supported().is_ok()
    }

    /// Creates the camera, or opens it when it exists already with this name. Needs no elevation, but
    /// the media source must be installed. `Error::Unsupported` before Windows 11.
    pub fn create(options: CameraOptions) -> Result<Self> {
        let format = options.validate()?;
        let mf = MediaFoundation::start()?;
        let sid = sys::current_user_sid()?;
        let id = contract::camera_id(&sid, &options.friendly_name);
        let camera = open_camera(&mf, &options.friendly_name)?;
        unsafe {
            camera.SetString(
                &GUID::from_u128(attributes::CAMERA_ID),
                &HSTRING::from(id.as_str()),
            )?;
            camera.SetString(
                &GUID::from_u128(attributes::PRODUCER_SID),
                &HSTRING::from(sid.as_str()),
            )?;
            camera.SetUINT32(&GUID::from_u128(attributes::WIDTH), format.width)?;
            camera.SetUINT32(&GUID::from_u128(attributes::HEIGHT), format.height)?;
            camera.SetUINT64(
                &GUID::from_u128(attributes::FRAME_RATE),
                (u64::from(format.fps_num) << 32) | u64::from(format.fps_den),
            )?;
            camera.SetUINT32(
                &GUID::from_u128(attributes::LAYOUT_VERSION),
                layout::VERSION,
            )?;
            camera
                .Start(None)
                .map_err(|e| Error::from_camera_call(e, "start the camera"))?;
        }
        drop(camera);
        drop(mf);
        Ok(Self {
            options,
            format,
            id,
            link: None,
            next_attempt: Instant::now(),
            idle: None,
        })
    }

    /// The camera's id, which names its shared memory and idle file.
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn options(&self) -> &CameraOptions {
        &self.options
    }

    /// True when an app has the camera open and frames reach it. Looks for the shared memory at most
    /// every 250 ms.
    pub fn is_connected(&mut self) -> Result<bool> {
        self.connect()?;
        Ok(self.link.is_some())
    }

    /// Sends one frame, tightly packed in `format` at the camera's size. Returns false when no app
    /// has the camera open, and the frame went nowhere.
    pub fn push_frame(&mut self, data: &[u8], format: PixelFormat) -> Result<bool> {
        check_size(data, format, &self.format)?;
        self.connect()?;
        let Some(link) = &mut self.link else {
            return Ok(false);
        };
        let (width, height) = (self.format.width, self.format.height);
        link.writer.write_frame(|slot| {
            to_nv12(data, format, width, height, slot).expect("size checked above")
        });
        Ok(true)
    }

    /// Sets the frame the camera shows while no app writes to it, such as `<App> is closed`. It is
    /// kept in `%ProgramData%\Skakel\VirtualCamera`, so the camera shows it after the app has gone.
    pub fn set_idle_frame(&mut self, data: &[u8], format: PixelFormat) -> Result<()> {
        check_size(data, format, &self.format)?;
        let mut nv12 = vec![0; self.format.frame_size()];
        to_nv12(
            data,
            format,
            self.format.width,
            self.format.height,
            &mut nv12,
        )
        .expect("size checked above");
        if let Some(link) = &mut self.link {
            link.writer.write_idle(|slot| slot.copy_from_slice(&nv12));
        }
        let file = contract::encode_idle_file(self.format.width, self.format.height, &nv12);
        self.idle = Some(nv12);
        write_idle_file(&self.id, &file)
    }

    /// Removes the camera from Windows. Apps that have it open lose it.
    pub fn remove(mut self) -> Result<()> {
        self.disconnect();
        remove_camera(&self.options.friendly_name)
    }

    fn connect(&mut self) -> Result<()> {
        if self.link.is_some() || Instant::now() < self.next_attempt {
            return Ok(());
        }
        self.next_attempt = Instant::now() + RETRY_INTERVAL;
        let Some(section) = Section::open(&contract::section_name(&self.id))? else {
            return Ok(());
        };
        let timeout = self.options.idle_timeout.as_millis().clamp(
            layout::MIN_IDLE_TIMEOUT_MS.into(),
            layout::MAX_IDLE_TIMEOUT_MS.into(),
        ) as u32;
        // SAFETY: `Link` keeps the writer before the section, so the writer is dropped first.
        let region = unsafe { section.region() };
        let mut writer = match FrameWriter::attach(region, std::process::id(), timeout) {
            Ok(writer) => writer,
            // The source is still writing the header; try again next time.
            Err(layout::HeaderError::NotReady) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        if writer.format() != self.format {
            writer.detach();
            return Err(Error::CameraMismatch {
                camera: writer.format(),
                requested: self.format,
            });
        }
        if let Some(idle) = &self.idle {
            writer.write_idle(|slot| slot.copy_from_slice(idle));
        }
        self.link = Some(Link {
            writer,
            _section: section,
        });
        Ok(())
    }

    fn disconnect(&mut self) {
        if let Some(link) = self.link.take() {
            link.writer.detach();
        }
    }
}

impl Drop for VirtualCamera {
    /// Tells the camera the producer is gone, so it shows the idle frame at once. The camera stays.
    fn drop(&mut self) {
        self.disconnect();
    }
}

/// Removes this user's camera of this name from Windows.
pub fn remove_camera(friendly_name: &str) -> Result<()> {
    let mf = MediaFoundation::start()?;
    let camera = open_camera(&mf, friendly_name)?;
    unsafe { camera.Remove() }.map_err(|e| Error::from_camera_call(e, "remove the camera"))
}

/// The camera is keyed off these parameters: the same ones open the same camera.
fn open_camera(mf: &MediaFoundation, friendly_name: &str) -> Result<IMFVirtualCamera> {
    mf.create_virtual_camera(
        MFVirtualCameraLifetime_System.0,
        MFVirtualCameraAccess_CurrentUser.0,
        friendly_name,
        contract::SOURCE_CLSID_STRING,
    )
    .map_err(|e| match e {
        Error::Windows(e) => Error::from_camera_call(e, "create the camera"),
        other => other,
    })
}

fn check_size(data: &[u8], format: PixelFormat, camera: &Format) -> Result<()> {
    let expected = format.frame_size(camera.width, camera.height);
    if data.len() == expected {
        Ok(())
    } else {
        Err(SizeMismatch {
            expected,
            actual: data.len(),
        }
        .into())
    }
}

/// Where a camera's idle frame is kept.
pub fn idle_file_path(camera_id: &str) -> Result<PathBuf> {
    let mut path = sys::program_data()?;
    path.extend(contract::IDLE_FOLDER);
    path.push(contract::idle_file_name(camera_id));
    Ok(path)
}

fn write_idle_file(camera_id: &str, contents: &[u8]) -> Result<()> {
    let path = idle_file_path(camera_id)?;
    if let Some(folder) = path.parent() {
        std::fs::create_dir_all(folder)?;
    }
    // Write beside it and rename over, so the media source never reads half a file.
    let partial = path.with_extension("idle.partial");
    std::fs::write(&partial, contents)?;
    std::fs::rename(&partial, &path)?;
    Ok(())
}
