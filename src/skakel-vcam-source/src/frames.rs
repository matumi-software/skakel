//! Which picture the camera sends: the producer's latest frame, or an idle frame.

use skakel_vcam::contract;
use skakel_vcam::convert::solid_nv12;
use skakel_vcam::layout::{self, Format, FrameReader, HeaderError};
use skakel_vcam::pacing::{Show, choose};
use skakel_vcam::section::Section;

use crate::config::Config;
use crate::log;

/// How often the source tries again to set up the shared memory after it could not.
const RETRY_MS: u64 = 500;

struct Link {
    reader: FrameReader,
    /// Keeps the memory the reader reads mapped. None in tests, which read plain memory.
    _section: Option<Section>,
}

/// The pictures one stream can send, and the shared memory it reads them from.
pub struct Frames {
    config: Config,
    link: Option<Link>,
    next_attempt_ms: u64,
    current: Vec<u8>,
    last_new_ms: Option<u64>,
    producer_idle: Option<Vec<u8>>,
    fallback_idle: Vec<u8>,
    /// Copies land here first and are swapped in only when whole, so a torn copy never replaces a
    /// good picture.
    scratch: Vec<u8>,
}

impl Frames {
    pub fn new(config: Config) -> Self {
        let format = config.format;
        let fallback_idle = config
            .camera_id
            .as_deref()
            .and_then(|id| load_idle_file(id, &format))
            .unwrap_or_else(|| builtin_idle(&format));
        Self {
            config,
            link: None,
            next_attempt_ms: 0,
            current: vec![0; format.frame_size()],
            last_new_ms: None,
            producer_idle: None,
            fallback_idle,
            scratch: vec![0; format.frame_size()],
        }
    }

    /// The picture to send at `now_ms`, after taking in whatever the producer wrote since the last call.
    pub fn select(&mut self, now_ms: u64) -> &[u8] {
        self.connect(now_ms);
        let (attached, timeout) = match &mut self.link {
            Some(link) => {
                if link.reader.read_new_frame(&mut self.scratch).is_some() {
                    std::mem::swap(&mut self.current, &mut self.scratch);
                    self.last_new_ms = Some(now_ms);
                }
                if link.reader.read_new_idle(&mut self.scratch).is_some() {
                    let idle = self.producer_idle.get_or_insert_with(Vec::new);
                    std::mem::swap(idle, &mut self.scratch);
                    if self.scratch.len() != idle.len() {
                        self.scratch = vec![0; idle.len()];
                    }
                }
                (
                    link.reader.producer_attached(),
                    link.reader.idle_timeout_ms(),
                )
            }
            None => (false, layout::DEFAULT_IDLE_TIMEOUT_MS),
        };
        match choose(attached, self.last_new_ms, now_ms, timeout) {
            Show::Frame => &self.current,
            Show::Idle => self.producer_idle.as_deref().unwrap_or(&self.fallback_idle),
        }
    }

    fn connect(&mut self, now_ms: u64) {
        if self.link.is_some() || now_ms < self.next_attempt_ms {
            return;
        }
        let Some(id) = self.config.camera_id.as_deref() else {
            return;
        };
        self.next_attempt_ms = now_ms + RETRY_MS;
        let format = self.config.format;
        let name = contract::section_name(id);
        let (section, created) = match Section::create(
            &name,
            format.total_size(),
            self.config.producer_sid.as_deref(),
        ) {
            Ok(done) => done,
            Err(e) => {
                log(&format!("cannot create {name}: {e}"));
                return;
            }
        };
        if created {
            layout::initialize(&section.region(), &format);
        }
        match FrameReader::open(section.region()) {
            Ok(reader) if reader.format() == format => {
                log(&format!(
                    "{} {name} for {}x{} at {}/{}",
                    if created { "created" } else { "opened" },
                    format.width,
                    format.height,
                    format.fps_num,
                    format.fps_den
                ));
                self.link = Some(Link {
                    reader,
                    _section: Some(section),
                });
            }
            Ok(reader) => log(&format!(
                "{name} holds {:?}, the camera is {format:?}; showing the idle frame",
                reader.format()
            )),
            // Another source instance is still writing the header.
            Err(HeaderError::NotReady) => self.next_attempt_ms = now_ms + 20,
            Err(e) => log(&format!("cannot use {name}: {e}")),
        }
    }
}

/// The idle frame the producer saved for after it has gone, if it is there and the right size.
fn load_idle_file(camera_id: &str, format: &Format) -> Option<Vec<u8>> {
    let path = skakel_vcam::idle_file_path(camera_id).ok()?;
    let expected = (contract::IDLE_FILE_HEADER + format.frame_size()) as u64;
    if std::fs::metadata(&path).ok()?.len() != expected {
        return None;
    }
    let file = std::fs::read(&path).ok()?;
    contract::decode_idle_file(&file, format).map(<[u8]>::to_vec)
}

/// Near black: what the camera shows when the producer never set an idle frame.
fn builtin_idle(format: &Format) -> Vec<u8> {
    solid_nv12(format.width, format.height, 24, 24, 24)
}

/// Copies a tightly packed NV12 frame into a buffer whose rows are `pitch` bytes apart, the chroma
/// plane straight after the luma plane's `height` rows.
pub fn copy_nv12_pitched(src: &[u8], width: usize, height: usize, dst: &mut [u8], pitch: usize) {
    assert!(pitch >= width && dst.len() >= pitch * (height + height / 2) - (pitch - width));
    for (row, line) in src
        .chunks_exact(width)
        .take(height + height / 2)
        .enumerate()
    {
        dst[row * pitch..row * pitch + width].copy_from_slice(line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use skakel_vcam::layout::{FrameWriter, Region};

    /// Frames reading a ring in plain memory, and a producer writing it.
    fn linked(format: Format, memory: &mut Vec<u64>) -> (Frames, FrameWriter) {
        memory.resize(format.total_size().div_ceil(8), 0);
        let region = unsafe { Region::new(memory.as_mut_ptr().cast(), memory.len() * 8) };
        layout::initialize(&region, &format);
        let mut frames = Frames::new(Config {
            format,
            camera_id: None,
            producer_sid: None,
        });
        frames.link = Some(Link {
            reader: FrameReader::open(region).unwrap(),
            _section: None,
        });
        (frames, FrameWriter::attach(region, 1, 1000).unwrap())
    }

    #[test]
    fn repeats_the_last_frame_then_goes_idle_then_comes_back() {
        let format = Format::new(16, 16, 30, 1).unwrap();
        let mut memory = Vec::new();
        let (mut frames, mut producer) = linked(format, &mut memory);
        let idle = builtin_idle(&format);
        assert_eq!(frames.select(0), idle.as_slice(), "nothing written yet");

        producer.write_frame(|slot| slot.fill(7));
        assert!(frames.select(100).iter().all(|&b| b == 7));
        // The producer stalls: the frame repeats up to the 1000 ms timeout, then the idle frame shows.
        assert!(frames.select(1100).iter().all(|&b| b == 7));
        assert_eq!(frames.select(1101), idle.as_slice());

        producer.write_frame(|slot| slot.fill(8));
        assert!(frames.select(1200).iter().all(|&b| b == 8), "frames return");
    }

    #[test]
    fn shows_the_producers_idle_frame_once_it_detaches() {
        let format = Format::new(16, 16, 30, 1).unwrap();
        let mut memory = Vec::new();
        let (mut frames, mut producer) = linked(format, &mut memory);
        producer.write_idle(|slot| slot.fill(42));
        producer.write_frame(|slot| slot.fill(7));
        assert!(frames.select(0).iter().all(|&b| b == 7));
        producer.detach();
        assert!(
            frames.select(10).iter().all(|&b| b == 42),
            "idle at once, no timeout"
        );
    }

    #[test]
    fn copies_rows_to_their_pitch() {
        let (w, h, pitch) = (4, 2, 6);
        let src: Vec<u8> = (1..=12).collect();
        let mut dst = vec![0; pitch * 3];
        copy_nv12_pitched(&src, w, h, &mut dst, pitch);
        assert_eq!(
            dst,
            [1, 2, 3, 4, 0, 0, 5, 6, 7, 8, 0, 0, 9, 10, 11, 12, 0, 0]
        );
    }

    #[test]
    fn copies_a_packed_frame_as_is() {
        let src: Vec<u8> = (0..384).map(|i| i as u8).collect();
        let mut dst = vec![0; 384];
        copy_nv12_pitched(&src, 16, 16, &mut dst, 16);
        assert_eq!(src, dst);
    }

    #[test]
    fn without_an_id_it_shows_the_builtin_idle_frame() {
        let format = Format::new(16, 16, 30, 1).unwrap();
        let mut frames = Frames::new(Config {
            format,
            camera_id: None,
            producer_sid: None,
        });
        assert_eq!(frames.select(0), builtin_idle(&format).as_slice());
        assert_eq!(frames.select(10_000), builtin_idle(&format).as_slice());
    }
}
