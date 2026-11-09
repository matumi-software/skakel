//! The names and identifiers both producers and the media source agree on. `docs/virtual-camera.md`
//! is the contract.

use crate::convert::fnv1a64;
use crate::layout::Format;

/// The media source's CLSID. It stays the same from version to version, so a camera created with
/// one version keeps working after an upgrade.
pub const SOURCE_CLSID: u128 = 0x8138410c_b0a8_4cbc_9e0e_5920362ed550;

/// The CLSID in the `{...}` form `MFCreateVirtualCamera` and the registry take.
pub const SOURCE_CLSID_STRING: &str = "{8138410C-B0A8-4CBC-9E0E-5920362ED550}";

/// Attributes the producer sets on the virtual camera. Frame Server hands them to the media source
/// when it activates it.
pub mod attributes {
    /// String: the camera id, which names the shared memory and the idle file.
    pub const CAMERA_ID: u128 = 0x2823b277_8caa_4866_b746_68f84ca14f41;
    /// UINT32: width in pixels.
    pub const WIDTH: u128 = 0xcf28fa9f_2299_4faa_8cb9_a39776b685de;
    /// UINT32: height in pixels.
    pub const HEIGHT: u128 = 0xb32ef9c4_4e8f_4d60_8df9_d6e8ecee1900;
    /// UINT64: frame rate, numerator in the high 32 bits and denominator in the low, as
    /// `MF_MT_FRAME_RATE` packs it.
    pub const FRAME_RATE: u128 = 0x6818edaf_afd8_4a30_8852_945669ae9cb0;
    /// String: the SID of the user whose producer may write the shared memory.
    pub const PRODUCER_SID: u128 = 0x0a7bd1e8_c693_4bff_8f51_4d15b4b7606a;
    /// UINT32: the shared memory layout version the producer speaks.
    pub const LAYOUT_VERSION: u128 = 0x52a2c5ab_38fe_4d3e_aa11_8045bb97aaf7;
}

/// What the media source uses when an attribute is missing: a camera the producer never set up.
pub const FALLBACK_FORMAT: Format = Format {
    width: 1280,
    height: 720,
    fps_num: 30,
    fps_den: 1,
};

/// A camera's id: FNV-1a 64 of `<user SID>\n<friendly name>` in UTF-8, as 16 lowercase hex digits.
/// The SID keeps two users' cameras of the same name apart.
pub fn camera_id(user_sid: &str, friendly_name: &str) -> String {
    format!(
        "{:016x}",
        fnv1a64(format!("{user_sid}\n{friendly_name}").as_bytes())
    )
}

/// True for a string `camera_id` could have made. The media source checks this before it builds a
/// kernel object name or a file name from an attribute.
pub fn is_camera_id(id: &str) -> bool {
    id.len() == 16
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The shared memory's kernel object name.
pub fn section_name(camera_id: &str) -> String {
    format!("Global\\Skakel.VirtualCamera.{camera_id}")
}

/// The idle file's name, in `%ProgramData%\Skakel\VirtualCamera`.
pub fn idle_file_name(camera_id: &str) -> String {
    format!("{camera_id}.idle")
}

/// The idle file's folder under `%ProgramData%`.
pub const IDLE_FOLDER: [&str; 2] = ["Skakel", "VirtualCamera"];

/// `SKVI` as it reads in the file.
pub const IDLE_FILE_MAGIC: u32 = u32::from_le_bytes(*b"SKVI");

/// Bytes before the frame in an idle file.
pub const IDLE_FILE_HEADER: usize = 16;

/// An idle file: magic, version 1, width and height as little-endian u32, then one NV12 frame.
pub fn encode_idle_file(width: u32, height: u32, nv12: &[u8]) -> Vec<u8> {
    let mut file = Vec::with_capacity(IDLE_FILE_HEADER + nv12.len());
    for value in [IDLE_FILE_MAGIC, 1, width, height] {
        file.extend_from_slice(&value.to_le_bytes());
    }
    file.extend_from_slice(nv12);
    file
}

/// The NV12 frame in an idle file, if the file is one and its size is `format`'s.
pub fn decode_idle_file<'a>(file: &'a [u8], format: &Format) -> Option<&'a [u8]> {
    let word = |i: usize| {
        file.get(i * 4..i * 4 + 4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    };
    let header_ok = word(0) == Some(IDLE_FILE_MAGIC)
        && word(1) == Some(1)
        && word(2) == Some(format.width)
        && word(3) == Some(format.height);
    (header_ok && file.len() == IDLE_FILE_HEADER + format.frame_size())
        .then(|| &file[IDLE_FILE_HEADER..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn camera_id_is_pinned() {
        let id = camera_id("S-1-5-21-1004336348-1177238915-682003330-512", "Tweeling");
        assert_eq!(id, CAMERA_ID_PIN);
        assert!(is_camera_id(&id));
        assert_eq!(
            section_name(&id),
            format!("Global\\Skakel.VirtualCamera.{CAMERA_ID_PIN}")
        );
    }

    const CAMERA_ID_PIN: &str = "313c3868b45ee1ae";

    #[test]
    fn camera_id_depends_on_the_user() {
        assert_ne!(
            camera_id("S-1-5-21-1", "Cam"),
            camera_id("S-1-5-21-2", "Cam")
        );
    }

    #[test]
    fn only_accepts_ids_it_could_have_made() {
        assert!(!is_camera_id("0123456789ABCDEF"));
        assert!(!is_camera_id("..\\..\\windows\\x"));
        assert!(!is_camera_id("0123456789abcde"));
    }

    #[test]
    fn idle_file_round_trips() {
        let format = Format::new(16, 16, 30, 1).unwrap();
        let frame: Vec<u8> = (0..format.frame_size()).map(|i| i as u8).collect();
        let file = encode_idle_file(16, 16, &frame);
        assert_eq!(&file[..4], b"SKVI");
        assert_eq!(decode_idle_file(&file, &format), Some(frame.as_slice()));
    }

    #[test]
    fn idle_file_of_another_size_is_ignored() {
        let format = Format::new(16, 16, 30, 1).unwrap();
        let other = Format::new(32, 16, 30, 1).unwrap();
        let file = encode_idle_file(32, 16, &vec![0; other.frame_size()]);
        assert_eq!(decode_idle_file(&file, &format), None);
        assert_eq!(decode_idle_file(&file[..20], &other), None);
        assert_eq!(decode_idle_file(b"SKV", &format), None);
    }
}
