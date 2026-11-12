//! What Skakel clients and servers share: the numbers, paths and names of protocol version 2, the
//! JSON contracts, certificate fingerprints, and the reasons a gRPC call is refused or ended. See
//! `docs/protocol.md` at the repository root.
//!
//! Discovery, the pairing code and the serial messages are their own crates, and the code generated
//! from the `.proto` files is `skakel-proto`; see `docs/parts.md`.
//!
//! # JSON
//!
//! Every body and message is UTF-8 JSON with camelCase names, written by serde, and read
//! exactly as written. An absent optional field is written as `null`, and read either way.

#![forbid(unsafe_code)]

mod contracts;
pub mod fingerprints;
mod grpc_code;
mod reasons;

pub use contracts::{SkakelApp, SkakelHello, SkakelInfo};
pub use grpc_code::GrpcCode;
pub use reasons::{
    ERROR_DOMAIN, MAX_REASON_LENGTH, Reason, STREAM_TYPE_CODE, STREAM_TYPE_DOMAIN_PREFIX,
    is_reason, stream_type_domain,
};

use std::time::Duration;

/// The protocol version this crate speaks.
pub const VERSION: u32 = 2;

/// The protocol versions this crate speaks, as a server lists them.
pub const VERSIONS: &[u32] = &[VERSION];

/// The unversioned info endpoint: `GET`, no token.
pub const INFO_PATH: &str = "/skakel/info";

/// Every versioned path starts with this.
pub const BASE_PATH: &str = "/skakel/v2";

/// Opens a pairing request: `POST`. Reveal, poll and withdraw are under `{PAIR_PATH}/{requestId}`.
pub const PAIR_PATH: &str = "/skakel/v2/pair";

/// OAuth 2.0 client credentials: `POST`.
pub const TOKEN_PATH: &str = "/skakel/v2/token";

/// The header that carries a pairing request's poll token.
pub const PAIR_TOKEN_HEADER: &str = "X-Pair-Token";

/// The access token claim that carries the client's generation.
pub const GENERATION_CLAIM: &str = "skakel_generation";

/// How long an access token lasts: 30 minutes.
pub const ACCESS_TOKEN_LIFETIME: Duration = Duration::from_secs(30 * 60);

/// How often both ends of a connection that carries gRPC send an HTTP/2 PING.
pub const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// How long an end that has heard nothing from the other, no PING answer and no other frame, waits
/// before it takes the connection for dead.
pub const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(30);

/// The largest message on the control service, counted as encoded: 1 MiB.
pub const CONTROL_MESSAGE_LIMIT: usize = 1024 * 1024;

/// The largest frame on the stream service, counted as encoded: 16 MiB.
pub const STREAM_MESSAGE_LIMIT: usize = 16 * 1024 * 1024;

/// How long a server waits for a stream's `open` frame.
pub const OPEN_TIMEOUT: Duration = Duration::from_secs(15);

/// The content type of a gRPC call. A request whose content type is this, or starts with
/// `application/grpc+`, is a gRPC call.
pub const GRPC_CONTENT_TYPE: &str = "application/grpc";

/// True for a content type that makes a request a gRPC call: `application/grpc`, or one that
/// starts with `application/grpc+`, with or without parameters.
pub fn is_grpc_content_type(content_type: &str) -> bool {
    let media = content_type.split(';').next().unwrap_or("").trim();
    media.eq_ignore_ascii_case(GRPC_CONTENT_TYPE)
        || media
            .get(..GRPC_CONTENT_TYPE.len() + 1)
            .is_some_and(|start| start.eq_ignore_ascii_case("application/grpc+"))
}

/// True for the name of an app's own gRPC service, `<package>.<Service>`: its package must not be
/// `skakel` or start with `skakel.`.
pub fn is_app_service_name(name: &str) -> bool {
    let package = name.rsplit_once('.').map_or("", |(package, _)| package);
    !package.is_empty() && package != "skakel" && !package.starts_with("skakel.")
}

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
        for path in [PAIR_PATH, TOKEN_PATH] {
            assert!(path.starts_with(&format!("{BASE_PATH}/")));
        }
        assert_eq!(BASE_PATH, "/skakel/v2");
        assert_eq!(PAIR_PATH, "/skakel/v2/pair");
        assert_eq!(TOKEN_PATH, "/skakel/v2/token");
    }

    #[test]
    fn lifetimes_are_the_ones_in_the_protocol() {
        assert_eq!(ACCESS_TOKEN_LIFETIME, Duration::from_secs(1800));
        assert_eq!(KEEP_ALIVE_INTERVAL, Duration::from_secs(15));
        assert_eq!(KEEP_ALIVE_TIMEOUT, Duration::from_secs(30));
        assert_eq!(OPEN_TIMEOUT, Duration::from_secs(15));
    }

    #[test]
    fn message_limits_are_the_ones_in_the_protocol() {
        assert_eq!(CONTROL_MESSAGE_LIMIT, 1 << 20);
        assert_eq!(STREAM_MESSAGE_LIMIT, 16 << 20);
    }

    #[test]
    fn a_grpc_call_is_told_by_its_content_type() {
        assert!(is_grpc_content_type("application/grpc"));
        assert!(is_grpc_content_type("application/grpc+proto"));
        assert!(is_grpc_content_type("Application/GRPC; charset=utf-8"));
        assert!(!is_grpc_content_type("application/grpc-web"));
        assert!(!is_grpc_content_type("application/grpcx"));
        assert!(!is_grpc_content_type("application/json"));
        assert!(!is_grpc_content_type(""));
    }

    #[test]
    fn an_apps_service_is_in_a_package_of_its_own() {
        assert!(is_app_service_name("koppel.v1.Devices"));
        assert!(is_app_service_name("skakelish.Things"));
        assert!(!is_app_service_name("skakel.v2.ControlService"));
        assert!(!is_app_service_name("skakel.Things"));
        assert!(!is_app_service_name("Things"));
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
