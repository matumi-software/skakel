//! The codes a stream's close frame carries.

use crate::hub::{CLOSING_REVOKED, CLOSING_ROTATED, CLOSING_STOPPING};

/// Closed normally.
pub const CLOSE_NORMAL: u16 = 1000;

/// The client was revoked.
pub const CLOSE_REVOKED: u16 = 4001;

/// The client's secret was rotated.
pub const CLOSE_ROTATED: u16 = 4002;

/// The server is stopping, or no longer serves this type.
pub const CLOSE_STOPPING: u16 = 4003;

/// The target went away (unplugged, removed).
pub const CLOSE_TARGET_GONE: u16 = 4004;

/// The first code a stream type may define for itself.
pub const CLOSE_FIRST_TYPE_DEFINED: u16 = 4100;

/// The last code a stream type may define for itself.
pub const CLOSE_LAST_TYPE_DEFINED: u16 = 4999;

/// The close code for one of the closing reasons (`revoked`, `rotated`, `stopping`), or `None` for
/// any other text.
pub fn close_code_for(reason: &str) -> Option<u16> {
    match reason {
        CLOSING_REVOKED => Some(CLOSE_REVOKED),
        CLOSING_ROTATED => Some(CLOSE_ROTATED),
        CLOSING_STOPPING => Some(CLOSE_STOPPING),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_code_for_maps_each_closing_reason() {
        assert_eq!(close_code_for("revoked"), Some(4001));
        assert_eq!(close_code_for("rotated"), Some(4002));
        assert_eq!(close_code_for("stopping"), Some(4003));
    }

    #[test]
    fn close_code_for_refuses_other_text() {
        assert_eq!(close_code_for("gone"), None);
        assert_eq!(close_code_for(""), None);
    }

    #[test]
    fn close_codes_are_the_numbers_in_the_protocol() {
        assert_eq!(CLOSE_NORMAL, 1000);
        assert_eq!(CLOSE_TARGET_GONE, 4004);
        assert_eq!(CLOSE_FIRST_TYPE_DEFINED, 4100);
        assert_eq!(CLOSE_LAST_TYPE_DEFINED, 4999);
    }
}
