//! The JSON bodies of the pairing calls.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Waiting for a person to type the code on the server.
pub const PAIR_WAITING: &str = "waiting";

/// The code matched. The poll that sees this carries the credentials, once.
pub const PAIR_APPROVED: &str = "approved";

/// A person refused it, or the code was typed wrong three times.
pub const PAIR_DENIED: &str = "denied";

/// The request ran out of time.
pub const PAIR_EXPIRED: &str = "expired";

/// Opens a pairing request: `POST /skakel/v1/pair`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairOpenRequest {
    /// 1 to 80 characters after trimming.
    #[serde(default)]
    pub client_name: Option<String>,
    /// The uppercase hex SHA-256 of the client's nonce (`commit`).
    #[serde(default)]
    pub commitment: Option<String>,
}

/// What the server answers to an open. Only the opener ever sees the poll token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairOpened {
    /// The request's handle, in the paths that follow.
    pub request_id: String,
    /// The server's nonce for the code.
    pub server_nonce: String,
    /// When the request runs out, as an RFC 3339 timestamp.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// Sent in the `X-Pair-Token` header to poll and to withdraw.
    pub poll_token: String,
}

/// Reveals the client's nonce: `POST /skakel/v1/pair/{requestId}/reveal`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairRevealRequest {
    /// The nonce the commitment was made from.
    #[serde(default)]
    pub client_nonce: Option<String>,
}

/// What a poll answers: `GET /skakel/v1/pair/{requestId}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairPoll {
    /// One of [`PAIR_WAITING`], [`PAIR_APPROVED`], [`PAIR_DENIED`] and [`PAIR_EXPIRED`]. Kept as
    /// text so a state added later still reads.
    pub state: String,
    /// Once approved: the client's ID on this server.
    #[serde(default)]
    pub client_id: Option<String>,
    /// Once approved: the client's secret. Handed over once.
    #[serde(default)]
    pub client_secret: Option<String>,
}

impl PairPoll {
    /// A poll that carries a state and nothing else.
    pub fn state(state: &str) -> Self {
        Self {
            state: state.to_owned(),
            client_id: None,
            client_secret: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn pair_states_are_the_words_in_the_protocol() {
        assert_eq!(
            [PAIR_WAITING, PAIR_APPROVED, PAIR_DENIED, PAIR_EXPIRED],
            ["waiting", "approved", "denied", "expired"]
        );
    }

    #[test]
    fn open_request_is_written_in_camel_case_with_the_commitment_after_the_name() {
        let request = PairOpenRequest {
            client_name: Some("Anna PC".into()),
            commitment: Some("AB".into()),
        };

        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"clientName":"Anna PC","commitment":"AB"}"#
        );
    }

    #[test]
    fn open_request_reads_fields_that_are_missing_or_null() {
        let request: PairOpenRequest = serde_json::from_str(r#"{"clientName":null}"#).unwrap();

        assert_eq!(request, PairOpenRequest::default());
    }

    #[test]
    fn opened_reads_a_timestamp_with_seven_decimals() {
        let opened: PairOpened = serde_json::from_str(
            r#"{"requestId":"r1","serverNonce":"sn","expiresAt":"2026-11-06T12:30:45.1234567+00:00","pollToken":"pt"}"#,
        )
        .unwrap();

        assert_eq!(opened.request_id, "r1");
        assert_eq!(opened.server_nonce, "sn");
        assert_eq!(opened.poll_token, "pt");
        assert_eq!(
            opened.expires_at,
            datetime!(2026-11-06 12:30:45.1234567 UTC)
        );
    }

    #[test]
    fn opened_reads_an_offset_that_is_not_utc() {
        let opened: PairOpened = serde_json::from_str(
            r#"{"requestId":"r1","serverNonce":"sn","expiresAt":"2026-11-06T14:30:45+02:00","pollToken":"pt"}"#,
        )
        .unwrap();

        assert_eq!(opened.expires_at, datetime!(2026-11-06 12:30:45 UTC));
    }

    #[test]
    fn opened_round_trips() {
        let opened = PairOpened {
            request_id: "r1".into(),
            server_nonce: "sn".into(),
            expires_at: datetime!(2026-11-06 12:30:45 UTC),
            poll_token: "pt".into(),
        };

        let json = serde_json::to_string(&opened).unwrap();

        assert_eq!(serde_json::from_str::<PairOpened>(&json).unwrap(), opened);
    }

    #[test]
    fn reveal_uses_camel_case() {
        let reveal = PairRevealRequest {
            client_nonce: Some("n".into()),
        };

        assert_eq!(
            serde_json::to_string(&reveal).unwrap(),
            r#"{"clientNonce":"n"}"#
        );
    }

    #[test]
    fn poll_writes_the_credentials_as_null_until_approved() {
        assert_eq!(
            serde_json::to_string(&PairPoll::state(PAIR_WAITING)).unwrap(),
            r#"{"state":"waiting","clientId":null,"clientSecret":null}"#
        );
    }

    #[test]
    fn poll_reads_an_approval_and_a_bare_state() {
        let approved: PairPoll =
            serde_json::from_str(r#"{"state":"approved","clientId":"c1","clientSecret":"s3"}"#)
                .unwrap();
        let bare: PairPoll = serde_json::from_str(r#"{"state":"denied"}"#).unwrap();

        assert_eq!(approved.client_id.as_deref(), Some("c1"));
        assert_eq!(approved.client_secret.as_deref(), Some("s3"));
        assert_eq!(bare, PairPoll::state(PAIR_DENIED));
    }
}
