//! What a call failed with, as errors that stay on an [`Error`]'s source for the log.

use super::*;

/// The server refused a token request, with OAuth's error code and the HTTP status.
#[derive(Debug)]
pub(crate) struct TokenRequestError {
    pub error: String,
    pub status: u16,
}

impl fmt::Display for TokenRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "The token request failed: {} ({}).",
            self.error, self.status
        )
    }
}

impl StdError for TokenRequestError {}

/// The server answered with a status the call did not expect.
#[derive(Debug)]
pub(crate) struct StatusError(pub u16);

impl fmt::Display for StatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "The server answered {}.", self.0)
    }
}

impl StdError for StatusError {}

/// A gRPC call that failed, with the status it ended with.
#[derive(Debug)]
pub(crate) struct GrpcStatus(pub Status);

impl fmt::Display for GrpcStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "The call ended with {:?}: {}",
            self.0.code(),
            self.0.message()
        )
    }
}

impl StdError for GrpcStatus {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.0)
    }
}

/// An answer the client cannot use: broken JSON, missing fields, values outside the limits, or more
/// than it reads.
#[derive(Debug)]
pub(crate) struct BadAnswer(pub String);

impl fmt::Display for BadAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl StdError for BadAnswer {}

pub(crate) fn bad_answer(text: impl Into<String>) -> Error {
    Error::caused(FailureKind::UnexpectedAnswer, BadAnswer(text.into()))
}
