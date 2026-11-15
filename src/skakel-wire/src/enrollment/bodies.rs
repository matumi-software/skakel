//! The JSON bodies of the enrolment calls, camelCase like every other Skakel body.

use serde::{Deserialize, Serialize};

/// `POST /skakel/v3/enroll/code`: the client's name and its password-exchange message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeStart {
    /// The name the client goes by, cleaned like a pairing name.
    pub client_name: String,
    /// The client's SPAKE2 message, base64url.
    pub pake: String,
}

/// The server's answer to [`CodeStart`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeStarted {
    /// Names this exchange in the confirm call.
    pub enroll_id: String,
    /// The server's SPAKE2 message, base64url.
    pub pake: String,
    /// When the exchange is dropped if it has not been confirmed (RFC 3339).
    pub expires_at: String,
}

/// `POST /skakel/v3/enroll/code/{enrollId}/confirm`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeConfirm {
    /// The client's confirmation MAC, base64url.
    pub mac: String,
}

/// `POST /skakel/v3/enroll/key`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyEnroll {
    /// The name the client goes by.
    pub client_name: String,
    /// 32 random bytes, base64url.
    pub nonce: String,
    /// The client's confirmation MAC, base64url.
    pub mac: String,
}

/// What a successful enrolment answers: the server's MAC, which the client checks before it trusts
/// anything, and the credentials.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Enrolled {
    /// The server's confirmation MAC, base64url.
    pub mac: String,
    /// The client's id.
    pub client_id: String,
    /// The client's secret.
    pub client_secret: String,
}

impl std::fmt::Debug for Enrolled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Enrolled")
            .field("client_id", &self.client_id)
            .field("client_secret", &"<hidden>")
            .finish()
    }
}
