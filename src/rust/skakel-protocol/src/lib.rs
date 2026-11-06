//! What Skakel clients and servers share: the numbers, paths and names of protocol version 1, the
//! JSON contracts, certificate fingerprints, the hub's messages and the stream close codes. See
//! `docs/protocol.md` at the repository root; this is the Rust side of `Skakel.Protocol`.
//!
//! Discovery, the pairing code and the serial messages are their own crates, see `docs/parts.md`.
//!
//! # JSON
//!
//! Every body and message is UTF-8 JSON with camelCase names, written by serde. The .NET side reads
//! more loosely (names in any case, numbers inside strings); this side reads exactly what both
//! write. An absent optional field is written as `null`, as .NET does, and read either way.

mod close_codes;
mod contracts;
pub mod fingerprints;
mod hub;

pub use close_codes::{
    CLOSE_FIRST_TYPE_DEFINED, CLOSE_LAST_TYPE_DEFINED, CLOSE_NORMAL, CLOSE_REVOKED, CLOSE_ROTATED,
    CLOSE_STOPPING, CLOSE_TARGET_GONE, close_code_for,
};
pub use contracts::{SkakelApp, SkakelHello, SkakelInfo, SkakelProblem};
pub use hub::{
    CLOSING_REVOKED, CLOSING_ROTATED, CLOSING_STOPPING, HUB_CERTIFICATES, HUB_CLOSING,
    HUB_NEXT_CERTIFICATE_RECEIVED, HUB_PREFIX, SkakelCertificates, SkakelClosing,
};

use std::time::Duration;

/// The protocol version this crate speaks.
pub const VERSION: u32 = 1;

/// The protocol versions this crate speaks, as a server lists them.
pub const VERSIONS: &[u32] = &[VERSION];

/// The unversioned info endpoint: `GET`, no token.
pub const INFO_PATH: &str = "/skakel/info";

/// Every versioned path starts with this.
pub const BASE_PATH: &str = "/skakel/v1";

/// Opens a pairing request: `POST`. Reveal, poll and withdraw are under `{PAIR_PATH}/{requestId}`.
pub const PAIR_PATH: &str = "/skakel/v1/pair";

/// OAuth 2.0 client credentials: `POST`.
pub const TOKEN_PATH: &str = "/skakel/v1/token";

/// Checks credentials: `GET` with a token.
pub const HELLO_PATH: &str = "/skakel/v1/hello";

/// Streams open at `{STREAMS_PATH}/{type}`.
pub const STREAMS_PATH: &str = "/skakel/v1/streams";

/// The header that carries a pairing request's poll token.
pub const PAIR_TOKEN_HEADER: &str = "X-Pair-Token";

/// The access token claim that carries the client's generation.
pub const GENERATION_CLAIM: &str = "skakel_generation";

/// How long an access token lasts: 30 minutes.
pub const ACCESS_TOKEN_LIFETIME: Duration = Duration::from_secs(30 * 60);

/// How often both ends of a stream ping.
pub const STREAM_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// How long an end of a stream waits for an answer to its ping before it gives up.
pub const STREAM_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(30);

/// The media type of a refusal's body.
pub const PROBLEM_CONTENT_TYPE: &str = "application/problem+json";

/// The most characters an app id has.
pub const MAX_APP_ID_LENGTH: usize = 32;

/// True for a stream type: one or more of `a-z`, `0-9` and `-`.
pub fn is_stream_type(text: &str) -> bool {
    !text.is_empty() && text.chars().all(is_name_character)
}

/// True for an app id: 1 to 32 of `a-z`, `0-9` and `-`.
pub fn is_app_id(text: &str) -> bool {
    (1..=MAX_APP_ID_LENGTH).contains(&text.len()) && text.chars().all(is_name_character)
}

fn is_name_character(c: char) -> bool {
    matches!(c, 'a'..='z' | '0'..='9' | '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_path_carries_the_version() {
        assert_eq!(BASE_PATH, format!("/skakel/v{VERSION}"));
    }

    #[test]
    fn paths_sit_under_the_base_path() {
        for path in [PAIR_PATH, TOKEN_PATH, HELLO_PATH, STREAMS_PATH] {
            assert!(path.starts_with(&format!("{BASE_PATH}/")));
        }
        assert_eq!(PAIR_PATH, "/skakel/v1/pair");
        assert_eq!(TOKEN_PATH, "/skakel/v1/token");
        assert_eq!(HELLO_PATH, "/skakel/v1/hello");
        assert_eq!(STREAMS_PATH, "/skakel/v1/streams");
    }

    #[test]
    fn lifetimes_are_the_ones_in_the_protocol() {
        assert_eq!(ACCESS_TOKEN_LIFETIME, Duration::from_secs(1800));
        assert_eq!(STREAM_KEEP_ALIVE_INTERVAL, Duration::from_secs(15));
        assert_eq!(STREAM_KEEP_ALIVE_TIMEOUT, Duration::from_secs(30));
    }

    #[test]
    fn is_stream_type_takes_lowercase_digits_and_dashes() {
        assert!(is_stream_type("serial"));
        assert!(is_stream_type("usb-2"));
        assert!(!is_stream_type(""));
        assert!(!is_stream_type("Serial"));
        assert!(!is_stream_type("a/b"));
        assert!(!is_stream_type("a_b"));
    }

    #[test]
    fn is_app_id_takes_one_to_thirty_two_name_characters() {
        assert!(is_app_id("koppel"));
        assert!(is_app_id(&"z".repeat(32)));
        assert!(!is_app_id(&"z".repeat(33)));
        assert!(!is_app_id(""));
        assert!(!is_app_id("Koppel"));
        assert!(!is_app_id("kop pel"));
    }
}
