//! The control hub's own messages and their names.

use serde::{Deserialize, Serialize};

/// What every Skakel message name starts with. Every other name belongs to the app, which may not
/// start one with it.
pub const HUB_PREFIX: &str = "Skakel";

/// Server to client, with [`SkakelCertificates`].
pub const HUB_CERTIFICATES: &str = "SkakelCertificates";

/// Server to client, with [`SkakelClosing`].
pub const HUB_CLOSING: &str = "SkakelClosing";

/// Client to server, with the next certificate's fingerprint, once the client stored it.
pub const HUB_NEXT_CERTIFICATE_RECEIVED: &str = "SkakelNextCertificateReceived";

/// The client was revoked. Its credentials are gone.
pub const CLOSING_REVOKED: &str = "revoked";

/// The client's secret was rotated. Tokens from before no longer work.
pub const CLOSING_ROTATED: &str = "rotated";

/// The server is stopping, or no longer serves what the connection was for.
pub const CLOSING_STOPPING: &str = "stopping";

/// The server's certificate and, while a handover is prepared, the next one. Sent as
/// [`HUB_CERTIFICATES`] when a hub connection opens and whenever either changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SkakelCertificates {
    /// The certificate the server presents now.
    pub fingerprint: String,
    /// The one it will present after the switch, or `None` when none is prepared.
    #[serde(default)]
    pub next_fingerprint: Option<String>,
}

/// Sent as [`HUB_CLOSING`] just before the server ends a client's connections and streams.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkakelClosing {
    /// One of [`CLOSING_REVOKED`], [`CLOSING_ROTATED`] and [`CLOSING_STOPPING`]. Kept as text so a
    /// reason added later still reads.
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hub_messages_start_with_the_prefix() {
        for name in [HUB_CERTIFICATES, HUB_CLOSING, HUB_NEXT_CERTIFICATE_RECEIVED] {
            assert!(name.starts_with(HUB_PREFIX));
        }
        assert_eq!(HUB_CERTIFICATES, "SkakelCertificates");
        assert_eq!(HUB_CLOSING, "SkakelClosing");
        assert_eq!(
            HUB_NEXT_CERTIFICATE_RECEIVED,
            "SkakelNextCertificateReceived"
        );
    }

    #[test]
    fn certificates_use_camel_case_and_write_a_missing_next_as_null() {
        let message = SkakelCertificates {
            fingerprint: "AB".into(),
            next_fingerprint: None,
        };

        assert_eq!(
            serde_json::to_string(&message).unwrap(),
            r#"{"fingerprint":"AB","nextFingerprint":null}"#
        );
    }

    #[test]
    fn certificates_read_a_next_that_is_null_or_left_out() {
        let with_next: SkakelCertificates =
            serde_json::from_str(r#"{"fingerprint":"AB","nextFingerprint":"CD"}"#).unwrap();
        let null: SkakelCertificates =
            serde_json::from_str(r#"{"fingerprint":"AB","nextFingerprint":null}"#).unwrap();
        let left_out: SkakelCertificates = serde_json::from_str(r#"{"fingerprint":"AB"}"#).unwrap();

        assert_eq!(with_next.next_fingerprint.as_deref(), Some("CD"));
        assert_eq!(null.next_fingerprint, None);
        assert_eq!(left_out, null);
    }

    #[test]
    fn closing_carries_its_reason() {
        let closing: SkakelClosing = serde_json::from_str(r#"{"reason":"revoked"}"#).unwrap();

        assert_eq!(closing.reason, CLOSING_REVOKED);
        assert_eq!(
            serde_json::to_string(&closing).unwrap(),
            r#"{"reason":"revoked"}"#
        );
    }
}
