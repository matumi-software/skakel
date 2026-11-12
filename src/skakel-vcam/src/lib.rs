//! A Windows virtual camera any app can feed. Teams, Zoom, browsers and the Camera app list it by
//! name; this crate creates it and sends it frames. See `docs/virtual-camera.md` at the repository
//! root for how it works and the contract with the media source.
//!
// The example uses the camera, which is Windows only: compiled there, ignored elsewhere.
#![cfg_attr(windows, doc = "```no_run")]
#![cfg_attr(not(windows), doc = "```ignore")]
//! # fn main() -> skakel_vcam::Result<()> {
//! use skakel_vcam::{CameraOptions, PixelFormat, VirtualCamera};
//!
//! let mut camera = VirtualCamera::create(CameraOptions::new("Tweeling", 1280, 720, 30))?;
//! let frame = vec![0u8; 1280 * 720 * 4];
//! camera.push_frame(&frame, PixelFormat::Bgra)?;
//! # Ok(())
//! # }
//! ```
//!
//! The camera needs Windows 11 and the media source installed (`skakel-vcam-install`, elevated).
//! Before Windows 11, `VirtualCamera::create` returns `Error::Unsupported`.
//!
//! The ring, the conversion and the pacing are plain Rust and build anywhere; the camera itself is
//! Windows only.

pub mod contract;
pub mod convert;
pub mod layout;
pub mod pacing;

#[cfg(windows)]
mod camera;
#[cfg(windows)]
pub mod install;
#[cfg(windows)]
pub mod section;
#[cfg(windows)]
pub mod sys;

#[cfg(windows)]
pub use camera::{CameraOptions, VirtualCamera, idle_file_path, remove_camera};
pub use convert::PixelFormat;

use std::fmt;

/// What went wrong.
#[derive(Debug)]
pub enum Error {
    /// Windows before 11, or Media Foundation missing. Not a failure of the camera: it cannot exist here.
    Unsupported(String),
    /// A name, size or rate the camera cannot have.
    InvalidArgument(String),
    /// A frame of the wrong size.
    FrameSize(convert::SizeMismatch),
    /// The camera's shared memory is there but cannot be used.
    SharedMemory(layout::HeaderError),
    /// The camera exists with another size or rate. Remove it and create it again.
    CameraMismatch {
        /// What the camera is.
        camera: layout::Format,
        /// What was asked for.
        requested: layout::Format,
    },
    /// A camera call failed; says which.
    Camera {
        /// What was being done.
        action: &'static str,
        /// What went wrong.
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The installer needs to run elevated.
    NotElevated,
    /// A file or the folder could not be read or written.
    Io(std::io::Error),
    /// A Windows call failed.
    #[cfg(windows)]
    Windows(windows::core::Error),
}

/// A result of this crate, with its [`Error`] unless another is given.
pub type Result<T, E = Error> = std::result::Result<T, E>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(why) => write!(f, "not supported here: {why}"),
            Self::InvalidArgument(why) => f.write_str(why),
            Self::FrameSize(e) => e.fmt(f),
            Self::SharedMemory(e) => e.fmt(f),
            Self::CameraMismatch { camera, requested } => write!(
                f,
                "the camera exists as {}x{} at {}/{} fps, not {}x{} at {}/{}; remove it and create it again",
                camera.width,
                camera.height,
                camera.fps_num,
                camera.fps_den,
                requested.width,
                requested.height,
                requested.fps_num,
                requested.fps_den
            ),
            Self::Camera { action, source } => write!(f, "could not {action}: {source}"),
            Self::NotElevated => f.write_str("this needs to run as administrator"),
            Self::Io(e) => e.fmt(f),
            #[cfg(windows)]
            Self::Windows(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::FrameSize(e) => Some(e),
            Self::SharedMemory(e) => Some(e),
            Self::Camera { source, .. } => Some(source.as_ref()),
            Self::Io(e) => Some(e),
            #[cfg(windows)]
            Self::Windows(e) => Some(e),
            _ => None,
        }
    }
}

impl From<layout::FormatError> for Error {
    fn from(e: layout::FormatError) -> Self {
        Self::InvalidArgument(e.to_string())
    }
}

impl From<layout::HeaderError> for Error {
    fn from(e: layout::HeaderError) -> Self {
        Self::SharedMemory(e)
    }
}

impl From<convert::SizeMismatch> for Error {
    fn from(e: convert::SizeMismatch) -> Self {
        Self::FrameSize(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[cfg(windows)]
impl From<windows::core::Error> for Error {
    fn from(e: windows::core::Error) -> Self {
        Self::Windows(e)
    }
}

#[cfg(windows)]
impl Error {
    /// A failed camera call, with a hint for the failures that have a known cause.
    pub(crate) fn from_camera_call(e: windows::core::Error, action: &'static str) -> Self {
        use windows::Win32::Foundation::{E_ACCESSDENIED, REGDB_E_CLASSNOTREG};
        let hint = match e.code() {
            REGDB_E_CLASSNOTREG => {
                "; the media source is not installed (run skakel-vcam-install as administrator)"
            }
            E_ACCESSDENIED => {
                "; camera access may be off in Settings > Privacy & security > Camera"
            }
            _ => "",
        };
        Self::Camera {
            action,
            source: Box::new(CameraCall { error: e, hint }),
        }
    }
}

/// A Windows error with a hint for the person, so the message says what to do and the error, with
/// its HRESULT, is still there for a program: it is this error's `source()`.
#[cfg(windows)]
#[derive(Debug)]
struct CameraCall {
    error: windows::core::Error,
    hint: &'static str,
}

#[cfg(windows)]
impl fmt::Display for CameraCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.error, self.hint)
    }
}

#[cfg(windows)]
impl std::error::Error for CameraCall {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use windows::Win32::Foundation::E_ACCESSDENIED;

    #[test]
    fn a_camera_call_error_keeps_its_hresult() {
        let error = Error::from_camera_call(E_ACCESSDENIED.into(), "start the camera");
        let text = error.to_string();
        assert!(text.contains("could not start the camera"), "{text}");
        assert!(text.contains("camera access may be off"), "{text}");
        let mut source = std::error::Error::source(&error);
        let mut code = None;
        while let Some(e) = source {
            if let Some(windows_error) = e.downcast_ref::<windows::core::Error>() {
                code = Some(windows_error.code());
            }
            source = e.source();
        }
        assert_eq!(code, Some(E_ACCESSDENIED));
    }
}
