//! The shared frame memory: its header, its slots and the lock-free ring a producer writes and the
//! media source reads. `docs/virtual-camera.md` is the contract; the offsets here follow it.
//!
//! Nothing in this module calls Windows, so it is tested on plain heap memory.

use std::fmt;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering, fence};

/// `SKVC` as it reads in memory.
pub const MAGIC: u32 = u32::from_le_bytes(*b"SKVC");
/// The layout version this crate writes and reads.
pub const VERSION: u32 = 1;
/// Bytes before the first slot.
pub const HEADER_SIZE: usize = 4096;
/// Frame slots in the ring. The idle frame has a slot of its own after them.
pub const SLOT_COUNT: usize = 3;
/// Each slot starts on a multiple of this.
pub const SLOT_ALIGN: usize = 64;
/// `NV12` as it reads in memory, the only pixel format the ring carries.
pub const FOURCC_NV12: u32 = u32::from_le_bytes(*b"NV12");
/// A slot or idle sequence number holds this while its frame is being written.
pub const WRITING: u64 = u64::MAX;
/// How long the media source repeats the last frame before it shows the idle frame, when the producer
/// leaves `idle_timeout_ms` at 0.
pub const DEFAULT_IDLE_TIMEOUT_MS: u32 = 2000;
/// The idle timeout a producer may ask for, at least.
pub const MIN_IDLE_TIMEOUT_MS: u32 = 100;
/// The idle timeout a producer may ask for, at most.
pub const MAX_IDLE_TIMEOUT_MS: u32 = 60_000;
/// Width and height are even and within these bounds.
pub const MIN_DIMENSION: u32 = 16;
/// Width and height are even and within these bounds.
pub const MAX_DIMENSION: u32 = 4096;
/// Frame rates run from 1 to this many frames a second.
pub const MAX_FPS: u32 = 120;

/// Byte offsets into the header. The source writes everything below `PRODUCER_STATE` once, before
/// `MAGIC`; the producer owns the rest.
pub mod offsets {
    pub const MAGIC: usize = 0;
    pub const VERSION: usize = 4;
    pub const HEADER_SIZE: usize = 8;
    pub const WIDTH: usize = 12;
    pub const HEIGHT: usize = 16;
    pub const FPS_NUM: usize = 20;
    pub const FPS_DEN: usize = 24;
    pub const FOURCC: usize = 28;
    pub const FRAME_SIZE: usize = 32;
    pub const SLOT_COUNT: usize = 36;
    pub const SLOT_SIZE: usize = 40;
    pub const TOTAL_SIZE: usize = 48;
    pub const PRODUCER_STATE: usize = 64;
    pub const PRODUCER_PID: usize = 68;
    pub const IDLE_TIMEOUT_MS: usize = 72;
    pub const FRAME_SEQ: usize = 80;
    pub const IDLE_SEQ: usize = 88;
    /// `SLOT_COUNT` sequence numbers of 8 bytes each.
    pub const SLOT_SEQ: usize = 96;
}

/// The size and rate of one camera's frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Format {
    pub width: u32,
    pub height: u32,
    pub fps_num: u32,
    pub fps_den: u32,
}

impl Format {
    /// A format the ring can carry: even width and height from 16 to 4096, 1 to 120 frames a second.
    pub fn new(width: u32, height: u32, fps_num: u32, fps_den: u32) -> Result<Self, FormatError> {
        let dimension_ok =
            |d: u32| (MIN_DIMENSION..=MAX_DIMENSION).contains(&d) && d.is_multiple_of(2);
        if !dimension_ok(width) || !dimension_ok(height) {
            return Err(FormatError::Size { width, height });
        }
        // At least 1 and at most MAX_FPS frames a second, without dividing.
        if fps_num == 0
            || fps_den == 0
            || fps_num < fps_den
            || u64::from(fps_num) > u64::from(MAX_FPS) * u64::from(fps_den)
        {
            return Err(FormatError::Rate { fps_num, fps_den });
        }
        Ok(Self {
            width,
            height,
            fps_num,
            fps_den,
        })
    }

    /// Bytes in one NV12 frame: the luma plane, then the interleaved chroma plane at half height.
    pub fn frame_size(&self) -> usize {
        self.width as usize * self.height as usize * 3 / 2
    }

    /// Bytes from the start of one slot to the next.
    pub fn slot_size(&self) -> usize {
        self.frame_size().next_multiple_of(SLOT_ALIGN)
    }

    /// Bytes in the whole shared memory: the header, the frame slots and the idle slot.
    pub fn total_size(&self) -> usize {
        HEADER_SIZE + (SLOT_COUNT + 1) * self.slot_size()
    }

    /// How long one frame lasts, in 100 ns units, rounded down.
    pub fn frame_duration_100ns(&self) -> i64 {
        (10_000_000 * u64::from(self.fps_den) / u64::from(self.fps_num)) as i64
    }
}

/// Why a size or rate is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormatError {
    Size { width: u32, height: u32 },
    Rate { fps_num: u32, fps_den: u32 },
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Size { width, height } => write!(
                f,
                "{width}x{height} is not a camera size: width and height must be even and from {MIN_DIMENSION} to {MAX_DIMENSION}"
            ),
            Self::Rate { fps_num, fps_den } => write!(
                f,
                "{fps_num}/{fps_den} is not a frame rate from 1 to {MAX_FPS} a second"
            ),
        }
    }
}

impl std::error::Error for FormatError {}

/// Why a header cannot be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderError {
    /// The magic is not there yet: the source is still writing the header.
    NotReady,
    /// Something other than a Skakel camera's memory.
    BadMagic(u32),
    /// A layout this crate does not speak.
    UnsupportedVersion(u32),
    /// The header contradicts itself or the memory is smaller than it says.
    Inconsistent,
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotReady => write!(f, "the camera's shared memory is not initialised yet"),
            Self::BadMagic(m) => write!(
                f,
                "the shared memory is not a Skakel camera's (magic {m:#010x})"
            ),
            Self::UnsupportedVersion(v) => write!(
                f,
                "the camera's shared memory has layout version {v}, this build speaks {VERSION}"
            ),
            Self::Inconsistent => write!(f, "the camera's shared memory header is inconsistent"),
        }
    }
}

impl std::error::Error for HeaderError {}

/// A block of memory holding a camera's header and slots: a mapped view of the shared memory, or a
/// plain buffer in tests.
#[derive(Clone, Copy, Debug)]
pub struct Region {
    base: NonNull<u8>,
    len: usize,
}

// The region is a raw view shared with other processes; every access below goes through atomics or
// the sequence numbers that guard a slot, so handing it to another thread is no different.
unsafe impl Send for Region {}
unsafe impl Sync for Region {}

impl Region {
    /// # Safety
    /// `base` must point to `len` bytes that stay mapped and writable for as long as the region and
    /// anything made from it are used, and must be aligned to 8 bytes.
    pub unsafe fn new(base: *mut u8, len: usize) -> Self {
        let base = NonNull::new(base).expect("region base is null");
        assert_eq!(
            base.as_ptr() as usize % 8,
            0,
            "region base is not aligned to 8 bytes"
        );
        Self { base, len }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn u32_at(&self, offset: usize) -> &AtomicU32 {
        assert!(offset + 4 <= self.len && offset.is_multiple_of(4));
        // In bounds and aligned, checked above; AtomicU32 has the layout of u32.
        unsafe { &*(self.base.as_ptr().add(offset) as *const AtomicU32) }
    }

    fn u64_at(&self, offset: usize) -> &AtomicU64 {
        assert!(offset + 8 <= self.len && offset.is_multiple_of(8));
        unsafe { &*(self.base.as_ptr().add(offset) as *const AtomicU64) }
    }

    fn bytes(&self, offset: usize, len: usize) -> *mut u8 {
        assert!(offset.checked_add(len).is_some_and(|end| end <= self.len));
        unsafe { self.base.as_ptr().add(offset) }
    }
}

fn slot_offset(format: &Format, slot: usize) -> usize {
    HEADER_SIZE + slot * format.slot_size()
}

fn idle_offset(format: &Format) -> usize {
    slot_offset(format, SLOT_COUNT)
}

fn slot_seq_offset(slot: usize) -> usize {
    offsets::SLOT_SEQ + slot * 8
}

/// Writes a fresh header. Only the media source does this, once, on memory it has just created
/// and which is still all zeros. The magic goes last, so a reader never sees half a header.
pub fn initialize(region: &Region, format: &Format) {
    assert!(
        region.len() >= format.total_size(),
        "region is smaller than the format needs"
    );
    let put = |offset, value| region.u32_at(offset).store(value, Ordering::Relaxed);
    put(offsets::VERSION, VERSION);
    put(offsets::HEADER_SIZE, HEADER_SIZE as u32);
    put(offsets::WIDTH, format.width);
    put(offsets::HEIGHT, format.height);
    put(offsets::FPS_NUM, format.fps_num);
    put(offsets::FPS_DEN, format.fps_den);
    put(offsets::FOURCC, FOURCC_NV12);
    put(offsets::FRAME_SIZE, format.frame_size() as u32);
    put(offsets::SLOT_COUNT, SLOT_COUNT as u32);
    put(offsets::SLOT_SIZE, format.slot_size() as u32);
    region
        .u64_at(offsets::TOTAL_SIZE)
        .store(format.total_size() as u64, Ordering::Relaxed);
    region
        .u32_at(offsets::MAGIC)
        .store(MAGIC, Ordering::Release);
}

/// The format a header describes, after checking that it is a version 1 header that fits the region.
pub fn read_format(region: &Region) -> Result<Format, HeaderError> {
    if region.len() < HEADER_SIZE {
        return Err(HeaderError::Inconsistent);
    }
    match region.u32_at(offsets::MAGIC).load(Ordering::Acquire) {
        0 => return Err(HeaderError::NotReady),
        MAGIC => {}
        other => return Err(HeaderError::BadMagic(other)),
    }
    let get = |offset| region.u32_at(offset).load(Ordering::Relaxed);
    let version = get(offsets::VERSION);
    if version != VERSION {
        return Err(HeaderError::UnsupportedVersion(version));
    }
    let format = Format::new(
        get(offsets::WIDTH),
        get(offsets::HEIGHT),
        get(offsets::FPS_NUM),
        get(offsets::FPS_DEN),
    )
    .map_err(|_| HeaderError::Inconsistent)?;
    let total = region.u64_at(offsets::TOTAL_SIZE).load(Ordering::Relaxed);
    let consistent = get(offsets::HEADER_SIZE) as usize == HEADER_SIZE
        && get(offsets::FOURCC) == FOURCC_NV12
        && get(offsets::FRAME_SIZE) as usize == format.frame_size()
        && get(offsets::SLOT_COUNT) as usize == SLOT_COUNT
        && get(offsets::SLOT_SIZE) as usize == format.slot_size()
        && total == format.total_size() as u64
        && format.total_size() <= region.len();
    if consistent {
        Ok(format)
    } else {
        Err(HeaderError::Inconsistent)
    }
}

/// The producer's side of the ring. It never waits: a frame goes into the slot after the latest one
/// whether or not the source is still reading the oldest.
#[derive(Debug)]
pub struct FrameWriter {
    region: Region,
    format: Format,
    idle_version: u64,
}

impl FrameWriter {
    /// Attaches to an initialised region and marks the producer present.
    pub fn attach(region: Region, pid: u32, idle_timeout_ms: u32) -> Result<Self, HeaderError> {
        let format = read_format(&region)?;
        region
            .u32_at(offsets::IDLE_TIMEOUT_MS)
            .store(idle_timeout_ms, Ordering::Relaxed);
        region
            .u32_at(offsets::PRODUCER_PID)
            .store(pid, Ordering::Relaxed);
        region
            .u32_at(offsets::PRODUCER_STATE)
            .store(1, Ordering::Release);
        // A producer that died mid-write leaves WRITING behind; count on from zero then.
        let idle_version = match region.u64_at(offsets::IDLE_SEQ).load(Ordering::Acquire) {
            WRITING => 0,
            v => v,
        };
        Ok(Self {
            region,
            format,
            idle_version,
        })
    }

    pub fn format(&self) -> Format {
        self.format
    }

    /// Writes the next frame. `fill` gets the slot, exactly one NV12 frame long. Returns the frame's
    /// sequence number.
    pub fn write_frame(&mut self, fill: impl FnOnce(&mut [u8])) -> u64 {
        let seq = self
            .region
            .u64_at(offsets::FRAME_SEQ)
            .load(Ordering::Relaxed)
            + 1;
        let slot = (seq % SLOT_COUNT as u64) as usize;
        self.region
            .u64_at(slot_seq_offset(slot))
            .store(WRITING, Ordering::Relaxed);
        fence(Ordering::Release);
        fill(self.slot_bytes(slot_offset(&self.format, slot)));
        let slot_seq = self.region.u64_at(slot_seq_offset(slot));
        let frame_seq = self.region.u64_at(offsets::FRAME_SEQ);
        slot_seq.store(seq, Ordering::Release);
        frame_seq.store(seq, Ordering::Release);
        seq
    }

    /// Replaces the idle frame. `fill` gets the idle slot, exactly one NV12 frame long.
    pub fn write_idle(&mut self, fill: impl FnOnce(&mut [u8])) {
        self.idle_version += 1;
        self.region
            .u64_at(offsets::IDLE_SEQ)
            .store(WRITING, Ordering::Relaxed);
        fence(Ordering::Release);
        fill(self.slot_bytes(idle_offset(&self.format)));
        self.region
            .u64_at(offsets::IDLE_SEQ)
            .store(self.idle_version, Ordering::Release);
    }

    /// Marks the producer gone, so the source shows the idle frame at once.
    pub fn detach(&self) {
        self.region
            .u32_at(offsets::PRODUCER_STATE)
            .store(0, Ordering::Release);
    }

    fn slot_bytes(&mut self, offset: usize) -> &mut [u8] {
        let len = self.format.frame_size();
        // The slot is ours to write: its sequence number says WRITING until we publish it, and a
        // reader that copies it meanwhile throws its copy away.
        unsafe { std::slice::from_raw_parts_mut(self.region.bytes(offset, len), len) }
    }
}

/// The media source's side of the ring.
#[derive(Debug)]
pub struct FrameReader {
    region: Region,
    format: Format,
    last_seq: u64,
    last_idle: u64,
}

impl FrameReader {
    /// Opens an initialised region. Frames written before this are not offered, so a frame left
    /// behind by a producer long gone never shows.
    pub fn open(region: Region) -> Result<Self, HeaderError> {
        let format = read_format(&region)?;
        let last_seq = region.u64_at(offsets::FRAME_SEQ).load(Ordering::Acquire);
        Ok(Self {
            region,
            format,
            last_seq,
            last_idle: 0,
        })
    }

    pub fn format(&self) -> Format {
        self.format
    }

    /// True while a producer is attached and has not said it is gone.
    pub fn producer_attached(&self) -> bool {
        self.region
            .u32_at(offsets::PRODUCER_STATE)
            .load(Ordering::Acquire)
            != 0
    }

    /// How long the producer asks the source to repeat its last frame, clamped to the allowed range.
    pub fn idle_timeout_ms(&self) -> u32 {
        match self
            .region
            .u32_at(offsets::IDLE_TIMEOUT_MS)
            .load(Ordering::Relaxed)
        {
            0 => DEFAULT_IDLE_TIMEOUT_MS,
            t => t.clamp(MIN_IDLE_TIMEOUT_MS, MAX_IDLE_TIMEOUT_MS),
        }
    }

    /// Copies the newest frame into `dst` if there is one this reader has not had yet and it was
    /// not overwritten while being copied. Returns its sequence number.
    pub fn read_new_frame(&mut self, dst: &mut [u8]) -> Option<u64> {
        let seq = self
            .region
            .u64_at(offsets::FRAME_SEQ)
            .load(Ordering::Acquire);
        if seq == 0 || seq == self.last_seq {
            return None;
        }
        let slot = (seq % SLOT_COUNT as u64) as usize;
        if !self.copy_guarded(
            slot_seq_offset(slot),
            seq,
            slot_offset(&self.format, slot),
            dst,
        ) {
            return None;
        }
        self.last_seq = seq;
        Some(seq)
    }

    /// Copies the producer's idle frame into `dst` if it changed since the last call. Returns its
    /// version.
    pub fn read_new_idle(&mut self, dst: &mut [u8]) -> Option<u64> {
        let version = self
            .region
            .u64_at(offsets::IDLE_SEQ)
            .load(Ordering::Acquire);
        if version == 0 || version == WRITING || version == self.last_idle {
            return None;
        }
        if !self.copy_guarded(offsets::IDLE_SEQ, version, idle_offset(&self.format), dst) {
            return None;
        }
        self.last_idle = version;
        Some(version)
    }

    /// The read half of the sequence lock: copy, then check the sequence number did not move.
    fn copy_guarded(
        &self,
        seq_offset: usize,
        expected: u64,
        data_offset: usize,
        dst: &mut [u8],
    ) -> bool {
        let len = self.format.frame_size();
        assert_eq!(dst.len(), len, "destination is not one frame long");
        let guard = self.region.u64_at(seq_offset);
        if guard.load(Ordering::Acquire) != expected {
            return false;
        }
        // The producer may be writing this slot again by now; the check below catches that, and the
        // torn copy is dropped.
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.region.bytes(data_offset, len),
                dst.as_mut_ptr(),
                len,
            )
        };
        fence(Ordering::Acquire);
        guard.load(Ordering::Relaxed) == expected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Zeroed memory aligned to 8 bytes, as a mapping would be.
    pub(crate) struct Buffer(Vec<u64>);

    impl Buffer {
        pub(crate) fn new(len: usize) -> Self {
            Self(vec![0; len.div_ceil(8)])
        }

        pub(crate) fn region(&mut self) -> Region {
            let len = self.0.len() * 8;
            unsafe { Region::new(self.0.as_mut_ptr().cast(), len) }
        }
    }

    fn setup(width: u32, height: u32) -> (Buffer, Region, Format) {
        let format = Format::new(width, height, 30, 1).unwrap();
        let mut buffer = Buffer::new(format.total_size());
        let region = buffer.region();
        initialize(&region, &format);
        (buffer, region, format)
    }

    #[test]
    fn sizes_follow_the_format() {
        let format = Format::new(1280, 720, 30, 1).unwrap();
        assert_eq!(format.frame_size(), 1_382_400);
        assert_eq!(format.slot_size(), 1_382_400);
        assert_eq!(format.total_size(), 4096 + 4 * 1_382_400);
        let odd = Format::new(18, 18, 30, 1).unwrap();
        assert_eq!(odd.frame_size(), 486);
        assert_eq!(odd.slot_size(), 512);
        assert_eq!(
            Format::new(1920, 1080, 30000, 1001)
                .unwrap()
                .frame_duration_100ns(),
            333_666
        );
    }

    #[test]
    fn refuses_formats_outside_the_limits() {
        assert!(Format::new(15, 16, 30, 1).is_err());
        assert!(Format::new(17, 16, 30, 1).is_err());
        assert!(Format::new(4098, 16, 30, 1).is_err());
        assert!(Format::new(16, 16, 0, 1).is_err());
        assert!(Format::new(16, 16, 121, 1).is_err());
        assert!(Format::new(16, 16, 1, 2).is_err());
        assert!(Format::new(16, 16, 240, 2).is_ok());
    }

    #[test]
    fn reads_back_what_initialize_wrote() {
        let (_buffer, region, format) = setup(32, 16);
        assert_eq!(read_format(&region), Ok(format));
    }

    #[test]
    fn header_is_not_ready_before_the_magic() {
        let mut buffer = Buffer::new(8192);
        assert_eq!(read_format(&buffer.region()), Err(HeaderError::NotReady));
    }

    #[test]
    fn refuses_another_version_and_a_short_region() {
        let (mut buffer, region, format) = setup(32, 16);
        region.u32_at(offsets::VERSION).store(2, Ordering::Relaxed);
        assert_eq!(
            read_format(&region),
            Err(HeaderError::UnsupportedVersion(2))
        );
        region
            .u32_at(offsets::VERSION)
            .store(VERSION, Ordering::Relaxed);
        let short = unsafe { Region::new(buffer.0.as_mut_ptr().cast(), format.total_size() - 8) };
        assert_eq!(read_format(&short), Err(HeaderError::Inconsistent));
    }

    #[test]
    fn reader_gets_each_new_frame_once() {
        let (_buffer, region, format) = setup(16, 16);
        let mut writer = FrameWriter::attach(region, 7, 0).unwrap();
        let mut reader = FrameReader::open(region).unwrap();
        let mut frame = vec![0; format.frame_size()];
        assert_eq!(reader.read_new_frame(&mut frame), None);

        writer.write_frame(|slot| slot.fill(1));
        assert_eq!(reader.read_new_frame(&mut frame), Some(1));
        assert!(frame.iter().all(|&b| b == 1));
        assert_eq!(reader.read_new_frame(&mut frame), None);

        for value in 2..=5 {
            writer.write_frame(|slot| slot.fill(value));
        }
        assert_eq!(reader.read_new_frame(&mut frame), Some(5));
        assert!(frame.iter().all(|&b| b == 5));
    }

    #[test]
    fn reader_skips_frames_written_before_it_opened() {
        let (_buffer, region, format) = setup(16, 16);
        let mut writer = FrameWriter::attach(region, 7, 0).unwrap();
        writer.write_frame(|slot| slot.fill(9));
        let mut reader = FrameReader::open(region).unwrap();
        let mut frame = vec![0; format.frame_size()];
        assert_eq!(reader.read_new_frame(&mut frame), None);
        writer.write_frame(|slot| slot.fill(10));
        assert_eq!(reader.read_new_frame(&mut frame), Some(2));
    }

    #[test]
    fn reader_drops_a_frame_being_written() {
        let (_buffer, region, format) = setup(16, 16);
        let mut writer = FrameWriter::attach(region, 7, 0).unwrap();
        let mut reader = FrameReader::open(region).unwrap();
        writer.write_frame(|slot| slot.fill(1));
        // The producer starts the next frame in the same slot and has not finished it.
        region
            .u64_at(slot_seq_offset(1))
            .store(WRITING, Ordering::Relaxed);
        let mut frame = vec![0; format.frame_size()];
        assert_eq!(reader.read_new_frame(&mut frame), None);
    }

    #[test]
    fn a_new_producer_counts_on() {
        let (_buffer, region, format) = setup(16, 16);
        let mut first = FrameWriter::attach(region, 7, 0).unwrap();
        first.write_frame(|slot| slot.fill(1));
        first.detach();
        let mut reader = FrameReader::open(region).unwrap();
        assert!(!reader.producer_attached());
        let mut second = FrameWriter::attach(region, 8, 500).unwrap();
        assert!(reader.producer_attached());
        assert_eq!(reader.idle_timeout_ms(), 500);
        assert_eq!(second.write_frame(|slot| slot.fill(2)), 2);
        let mut frame = vec![0; format.frame_size()];
        assert_eq!(reader.read_new_frame(&mut frame), Some(2));
    }

    #[test]
    fn idle_frame_is_read_when_it_changes() {
        let (_buffer, region, format) = setup(16, 16);
        let mut writer = FrameWriter::attach(region, 7, 0).unwrap();
        let mut reader = FrameReader::open(region).unwrap();
        let mut frame = vec![0; format.frame_size()];
        assert_eq!(reader.read_new_idle(&mut frame), None);
        writer.write_idle(|slot| slot.fill(42));
        assert_eq!(reader.read_new_idle(&mut frame), Some(1));
        assert!(frame.iter().all(|&b| b == 42));
        assert_eq!(reader.read_new_idle(&mut frame), None);
        writer.write_idle(|slot| slot.fill(43));
        assert_eq!(reader.read_new_idle(&mut frame), Some(2));
    }

    #[test]
    fn idle_timeout_defaults_and_clamps() {
        let (_buffer, region, _) = setup(16, 16);
        let reader = FrameReader::open(region).unwrap();
        assert_eq!(reader.idle_timeout_ms(), DEFAULT_IDLE_TIMEOUT_MS);
        FrameWriter::attach(region, 1, 5).unwrap();
        assert_eq!(reader.idle_timeout_ms(), MIN_IDLE_TIMEOUT_MS);
        FrameWriter::attach(region, 1, 10_000_000).unwrap();
        assert_eq!(reader.idle_timeout_ms(), MAX_IDLE_TIMEOUT_MS);
    }

    /// A scripted ring: a 16x16 camera, producer 4242 with a 1500 ms timeout, frames
    /// 1 to 4 where byte i of frame k is k * 31 + i * 7, and an idle frame where byte i is i * 3.
    fn scripted_ring() -> Vec<u8> {
        let format = Format::new(16, 16, 30, 1).unwrap();
        let mut buffer = Buffer::new(format.total_size());
        let region = buffer.region();
        initialize(&region, &format);
        let mut writer = FrameWriter::attach(region, 4242, 1500).unwrap();
        for k in 1..=4u32 {
            writer.write_frame(|slot| {
                slot.iter_mut()
                    .enumerate()
                    .for_each(|(i, b)| *b = (k * 31 + i as u32 * 7) as u8)
            });
        }
        writer.write_idle(|slot| {
            slot.iter_mut()
                .enumerate()
                .for_each(|(i, b)| *b = (i * 3) as u8)
        });
        let bytes: Vec<u8> = buffer.0.iter().flat_map(|w| w.to_le_bytes()).collect();
        bytes[..format.total_size()].to_vec()
    }

    #[test]
    fn pins_the_bytes_of_a_scripted_ring() {
        // Skakel.VirtualCamera.Tests pins the same hash for the same script, so a ring either side
        // writes is byte for byte the ring the other writes.
        let bytes = scripted_ring();
        assert_eq!(bytes.len(), 4096 + 4 * 384);
        assert_eq!(&bytes[..4], b"SKVC");
        assert_eq!(
            format!("{:016x}", crate::convert::fnv1a64(&bytes)),
            SCRIPTED_RING_FNV
        );
    }

    const SCRIPTED_RING_FNV: &str = "2600a0f3fa9b098c";

    #[test]
    fn reads_a_scripted_ring_written_elsewhere() {
        let format = Format::new(16, 16, 30, 1).unwrap();
        let mut buffer = Buffer::new(format.total_size());
        let region = buffer.region();
        initialize(&region, &format);
        let mut reader = FrameReader::open(region).unwrap();
        // The bytes arrive as they would from another process.
        let scripted = scripted_ring();
        unsafe {
            std::ptr::copy_nonoverlapping(
                scripted.as_ptr(),
                buffer.0.as_mut_ptr().cast::<u8>(),
                scripted.len(),
            )
        };
        assert!(reader.producer_attached());
        assert_eq!(reader.idle_timeout_ms(), 1500);
        let mut frame = vec![0; format.frame_size()];
        assert_eq!(reader.read_new_frame(&mut frame), Some(4));
        assert!(
            frame
                .iter()
                .enumerate()
                .all(|(i, &b)| b == (4 * 31 + i as u32 * 7) as u8)
        );
        assert_eq!(reader.read_new_idle(&mut frame), Some(1));
        assert!(frame.iter().enumerate().all(|(i, &b)| b == (i * 3) as u8));
    }

    #[test]
    fn frames_survive_a_writer_on_another_thread() {
        let (_buffer, region, format) = setup(64, 32);
        let mut reader = FrameReader::open(region).unwrap();
        let writer = std::thread::spawn(move || {
            let mut writer = FrameWriter::attach(region, 7, 0).unwrap();
            for n in 1..=2000u64 {
                writer.write_frame(|slot| slot.fill((n % 251) as u8));
            }
        });
        let mut frame = vec![0; format.frame_size()];
        let mut seen = 0;
        while !writer.is_finished() || seen == 0 {
            if let Some(seq) = reader.read_new_frame(&mut frame) {
                let expected = (seq % 251) as u8;
                assert!(frame.iter().all(|&b| b == expected), "torn frame {seq}");
                seen += 1;
            }
        }
        writer.join().unwrap();
        assert!(seen > 0);
    }
}
