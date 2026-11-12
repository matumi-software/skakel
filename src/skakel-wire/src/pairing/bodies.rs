//! The JSON bodies of the pairing calls.

use std::fmt;

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

/// Opens a pairing request: `POST /skakel/v2/pair`.
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

/// What the server answers to an open. Only the opener ever sees the poll token. `Debug` leaves
/// the poll token and the server's nonce out.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Reveals the client's nonce: `POST /skakel/v2/pair/{requestId}/reveal`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairRevealRequest {
    /// The nonce the commitment was made from.
    #[serde(default)]
    pub client_nonce: Option<String>,
}

/// What a poll answers: `GET /skakel/v2/pair/{requestId}`. `Debug` leaves the client's secret out.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairPoll {
    /// Where the request stands. A state added later reads as [`PairState::Unknown`].
    pub state: PairState,
    /// Once approved: the client's ID on this server.
    #[serde(default)]
    pub client_id: Option<String>,
    /// Once approved: the client's secret. Handed over once.
    #[serde(default)]
    pub client_secret: Option<String>,
}

impl PairPoll {
    /// A poll that carries a state and nothing else.
    pub fn state(state: impl Into<PairState>) -> Self {
        Self {
            state: state.into(),
            client_id: None,
            client_secret: None,
        }
    }
}

impl fmt::Debug for PairOpened {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairOpened")
            .field("request_id", &self.request_id)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for PairPoll {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairPoll")
            .field("state", &self.state)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<hidden>"),
            )
            .finish()
    }
}

/// Where a pairing request stands, as a poll says it. On the wire it is the lowercase word of the
/// protocol ([`PAIR_WAITING`] and the others); a word this version does not know is kept in
/// [`PairState::Unknown`], so a state added later still reads.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PairState {
    /// Waiting for a person to type the code on the server.
    Waiting,
    /// The code matched. The poll that sees this carries the credentials, once.
    Approved,
    /// A person refused it, or the code was typed wrong three times.
    Denied,
    /// The request ran out of time.
    Expired,
    /// A word this version does not know.
    Unknown(String),
}

impl PairState {
    /// The word the protocol writes for the state.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Waiting => PAIR_WAITING,
            Self::Approved => PAIR_APPROVED,
            Self::Denied => PAIR_DENIED,
            Self::Expired => PAIR_EXPIRED,
            Self::Unknown(word) => word,
        }
    }
}

impl From<&str> for PairState {
    fn from(word: &str) -> Self {
        match word {
            PAIR_WAITING => Self::Waiting,
            PAIR_APPROVED => Self::Approved,
            PAIR_DENIED => Self::Denied,
            PAIR_EXPIRED => Self::Expired,
            other => Self::Unknown(other.to_owned()),
        }
    }
}

impl Serialize for PairState {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for PairState {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(|word| Self::from(word.as_str()))
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
            serde_json::to_string(&PairPoll::state(PairState::Waiting)).unwrap(),
            r#"{"state":"waiting","clientId":null,"clientSecret":null}"#
        );
    }

    #[test]
    fn debug_leaves_out_the_secrets() {
        let opened = PairOpened {
            request_id: "r1".into(),
            server_nonce: "the-server-nonce".into(),
            expires_at: datetime!(2026-11-06 12:30:45 UTC),
            poll_token: "the-poll-token".into(),
        };
        let poll = PairPoll {
            state: PairState::Approved,
            client_id: Some("c1".into()),
            client_secret: Some("the-client-secret".into()),
        };

        let shown = format!("{opened:?} {poll:?}");

        for secret in ["the-server-nonce", "the-poll-token", "the-client-secret"] {
            assert!(!shown.contains(secret), "{shown}");
        }
        assert!(shown.contains("r1") && shown.contains("c1"), "{shown}");
    }

    #[test]
    fn a_state_is_its_word_and_a_word_not_known_is_kept() {
        for (state, word) in [
            (PairState::Waiting, "waiting"),
            (PairState::Approved, "approved"),
            (PairState::Denied, "denied"),
            (PairState::Expired, "expired"),
        ] {
            assert_eq!(
                serde_json::to_string(&state).unwrap(),
                format!("\"{word}\"")
            );
            assert_eq!(
                serde_json::from_str::<PairState>(&format!("\"{word}\"")).unwrap(),
                state
            );
        }
        let later: PairPoll = serde_json::from_str(r#"{"state":"locked"}"#).unwrap();

        assert_eq!(later.state, PairState::Unknown("locked".into()));
        assert_eq!(
            serde_json::to_string(&later).unwrap(),
            r#"{"state":"locked","clientId":null,"clientSecret":null}"#
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
        assert_eq!(bare, PairPoll::state(PairState::Denied));
        assert_eq!(PairPoll::state(PAIR_DENIED), bare);
    }
}
