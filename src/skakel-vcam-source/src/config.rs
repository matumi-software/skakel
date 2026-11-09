//! What the camera is, from the attributes the producer set on it.

use windows::Win32::Media::MediaFoundation::IMFAttributes;
use windows::core::{GUID, PWSTR};

use skakel_vcam::contract::{self, FALLBACK_FORMAT, attributes};
use skakel_vcam::layout::{self, Format};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub format: Format,
    /// None when the producer set no usable id or speaks another layout: the camera then shows only
    /// its built-in idle frame.
    pub camera_id: Option<String>,
    pub producer_sid: Option<String>,
}

impl Config {
    /// Checks every value; anything missing or out of range falls back to the defaults.
    pub fn from_values(
        width: Option<u32>,
        height: Option<u32>,
        frame_rate: Option<u64>,
        camera_id: Option<String>,
        producer_sid: Option<String>,
        layout_version: Option<u32>,
    ) -> Self {
        let format = match (width, height, frame_rate) {
            (Some(w), Some(h), Some(rate)) => {
                Format::new(w, h, (rate >> 32) as u32, rate as u32).unwrap_or(FALLBACK_FORMAT)
            }
            _ => FALLBACK_FORMAT,
        };
        let speaks_our_layout = layout_version.is_none_or(|v| v == layout::VERSION);
        let camera_id = camera_id.filter(|id| speaks_our_layout && contract::is_camera_id(id));
        Self {
            format,
            camera_id,
            producer_sid,
        }
    }

    pub fn from_attributes(store: &IMFAttributes) -> Self {
        let key = GUID::from_u128;
        unsafe {
            Self::from_values(
                store.GetUINT32(&key(attributes::WIDTH)).ok(),
                store.GetUINT32(&key(attributes::HEIGHT)).ok(),
                store.GetUINT64(&key(attributes::FRAME_RATE)).ok(),
                string(store, attributes::CAMERA_ID),
                string(store, attributes::PRODUCER_SID),
                store.GetUINT32(&key(attributes::LAYOUT_VERSION)).ok(),
            )
        }
    }
}

fn string(store: &IMFAttributes, key: u128) -> Option<String> {
    let mut text = PWSTR::null();
    let mut len = 0;
    unsafe {
        store
            .GetAllocatedString(&GUID::from_u128(key), &mut text, &mut len)
            .ok()?;
        let value = text.to_string().ok();
        windows::Win32::System::Com::CoTaskMemFree(Some(text.0 as *const _));
        value.filter(|v| v.len() <= 256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0123456789abcdef";

    #[test]
    fn takes_the_producers_values() {
        let config = Config::from_values(
            Some(1920),
            Some(1080),
            Some((60 << 32) | 1),
            Some(ID.into()),
            Some("S-1-5-21-1".into()),
            Some(1),
        );
        assert_eq!(config.format, Format::new(1920, 1080, 60, 1).unwrap());
        assert_eq!(config.camera_id.as_deref(), Some(ID));
        assert_eq!(config.producer_sid.as_deref(), Some("S-1-5-21-1"));
    }

    #[test]
    fn falls_back_without_a_size() {
        let config = Config::from_values(None, None, None, None, None, None);
        assert_eq!(config.format, FALLBACK_FORMAT);
        assert_eq!(config.camera_id, None);
    }

    #[test]
    fn falls_back_on_a_size_out_of_range() {
        let config = Config::from_values(
            Some(99_999),
            Some(1080),
            Some((30 << 32) | 1),
            Some(ID.into()),
            None,
            None,
        );
        assert_eq!(config.format, FALLBACK_FORMAT);
        assert_eq!(config.camera_id.as_deref(), Some(ID));
    }

    #[test]
    fn ignores_an_id_it_could_not_have_made_or_another_layout() {
        let bad = Config::from_values(None, None, None, Some("..\\x".into()), None, None);
        assert_eq!(bad.camera_id, None);
        let newer = Config::from_values(None, None, None, Some(ID.into()), None, Some(2));
        assert_eq!(newer.camera_id, None);
    }
}
