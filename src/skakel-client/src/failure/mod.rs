//! What went wrong talking to a server, as a fixed set of kinds with fixed wording. The detail of a
//! failure goes to the log and stays on [`Error::source`], never into the message, so the wording
//! cannot be used to probe addresses and ports.

mod causes;
mod classify;

pub(crate) use self::causes::*;
pub(crate) use self::classify::is_unreachable;
use self::classify::*;

use std::error::Error as StdError;
use std::fmt;
use std::io;

use skakel_wire::{Reason, VERSIONS};
use tonic::{Code, Status};

/// What went wrong. An app shows [`Failure::message`] and acts on the kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FailureKind {
    /// Nothing answered at the server's address: refused, timed out, no route, or a name that does
    /// not resolve.
    Unreachable,
    /// The server presented a certificate the client does not trust.
    CertificateMismatch,
    /// The server refused the client ID or secret.
    RejectedCredentials,
    /// The server issued a token but then refused it: it no longer knows the client.
    ClientUnknown,
    /// The server and the client have no protocol version in common.
    VersionMismatch,
    /// Something answered, but not the way a Skakel server does.
    UnexpectedAnswer,
    /// The server is taking no more requests from this address for now.
    TooManyRequests,
    /// The server revoked the client. Its credentials are gone.
    Revoked,
    /// The server gave the client a new secret, so the one it holds no longer works.
    Rotated,
    /// The server is stopping.
    ServerStopping,
    /// The connection to the server ended without the server saying why.
    ConnectionLost,
    /// The link is not connected, so the call could not be made.
    NotConnected,
    /// The server refused the pairing request, or the code was typed wrong three times.
    PairingDenied,
    /// The pairing request ran out before anyone typed the code.
    PairingExpired,
    /// The call was made with arguments that cannot be sent: a path that leaves the server, a
    /// stream type with characters outside `a-z`, `0-9` and `-`, or an empty port id. A bug in the
    /// app, not something a person can mend.
    InvalidRequest,
}

impl FailureKind {
    /// The kind as a camelCase word, such as `certificateMismatch`, for an app's API or UI.
    pub fn code(self) -> &'static str {
        match self {
            Self::Unreachable => "unreachable",
            Self::CertificateMismatch => "certificateMismatch",
            Self::RejectedCredentials => "rejectedCredentials",
            Self::ClientUnknown => "clientUnknown",
            Self::VersionMismatch => "versionMismatch",
            Self::UnexpectedAnswer => "unexpectedAnswer",
            Self::TooManyRequests => "tooManyRequests",
            Self::Revoked => "revoked",
            Self::Rotated => "rotated",
            Self::ServerStopping => "serverStopping",
            Self::ConnectionLost => "connectionLost",
            Self::NotConnected => "notConnected",
            Self::PairingDenied => "pairingDenied",
            Self::PairingExpired => "pairingExpired",
            Self::InvalidRequest => "invalidRequest",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::Unreachable => {
                "Could not reach the server. Check the address and that the server is running."
            }
            Self::CertificateMismatch => {
                "The server's certificate does not match the one this app trusts. If the server has a new certificate, pair with it again."
            }
            Self::RejectedCredentials => {
                "The server refused this client's ID or secret. Pair with the server again."
            }
            Self::ClientUnknown => {
                "The server accepted the token but no longer knows this client. Pair with the server again."
            }
            Self::VersionMismatch => {
                "This server and this app speak different versions of Skakel. Update the older one."
            }
            Self::UnexpectedAnswer => "The server did not answer like a Skakel server.",
            Self::TooManyRequests => {
                "The server is taking no more requests from here for now. Try again in a few minutes."
            }
            Self::Revoked => "The server revoked this client. Pair with the server again.",
            Self::Rotated => {
                "The server gave this client a new secret. Pair with the server again."
            }
            Self::ServerStopping => "The server is stopping.",
            Self::ConnectionLost => "The connection to the server was lost.",
            Self::NotConnected => "Not connected to the server.",
            Self::PairingDenied => "The server refused the pairing request.",
            Self::PairingExpired => "Nobody typed the code on the server in time. Start again.",
            Self::InvalidRequest => "The request is not one this app can send.",
        }
    }
}

/// A failure as a person sees it: one of a fixed set of kinds, each with fixed wording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    kind: FailureKind,
    message: String,
}

impl Failure {
    /// The failure of this kind with its fixed wording. For [`FailureKind::VersionMismatch`],
    /// [`Failure::version_mismatch`] names the versions.
    pub(crate) fn of(kind: FailureKind) -> Self {
        Self {
            kind,
            message: kind.message().to_owned(),
        }
    }

    /// The server speaks none of this client's protocol versions, worded with both sides' versions
    /// and which one to update, such as "This server speaks Skakel 4 and this app speaks Skakel 3.
    /// Update the app."
    pub(crate) fn version_mismatch(server_versions: &[u32]) -> Self {
        let Some(highest) = server_versions.iter().max() else {
            return Self::of(FailureKind::VersionMismatch);
        };
        let ours: &[u32] = VERSIONS;
        let update = if Some(highest) > ours.iter().max() {
            "the app"
        } else {
            "the server"
        };
        Self {
            kind: FailureKind::VersionMismatch,
            message: format!(
                "This server speaks Skakel {} and this app speaks Skakel {}. Update {update}.",
                list(server_versions),
                list(ours)
            ),
        }
    }

    /// What kind of failure.
    pub fn kind(&self) -> FailureKind {
        self.kind
    }

    /// The kind as a camelCase word, such as `certificateMismatch`.
    pub fn code(&self) -> &'static str {
        self.kind.code()
    }

    /// What to tell a person.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// Versions as people write them: `1`, `1 and 2`, `1, 2 and 3`.
fn list(versions: &[u32]) -> String {
    let mut words: Vec<u32> = versions.to_vec();
    words.sort_unstable();
    words.dedup();
    let words: Vec<String> = words.iter().map(u32::to_string).collect();
    match words.as_slice() {
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
        [] => String::new(),
    }
}

/// A call to a server failed. [`Error::failure`] is what to tell a person; the cause, for the log,
/// is [`Error::source`].
#[derive(Debug)]
pub struct Error {
    failure: Failure,
    source: Option<Box<dyn StdError + Send + Sync>>,
}

/// What a call to a server gives.
pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    /// A failure with no cause beyond itself.
    pub(crate) fn new(failure: Failure) -> Self {
        Self {
            failure,
            source: None,
        }
    }

    /// A failure and what caused it.
    pub(crate) fn with_source(
        failure: Failure,
        source: impl Into<Box<dyn StdError + Send + Sync>>,
    ) -> Self {
        Self {
            failure,
            source: Some(source.into()),
        }
    }

    /// An error of this kind with its fixed wording.
    pub(crate) fn of(kind: FailureKind) -> Self {
        Self::new(Failure::of(kind))
    }

    /// An error of this kind that something caused.
    pub(crate) fn caused(
        kind: FailureKind,
        source: impl Into<Box<dyn StdError + Send + Sync>>,
    ) -> Self {
        Self::with_source(Failure::of(kind), source)
    }

    /// What went wrong.
    pub fn failure(&self) -> &Failure {
        &self.failure
    }

    /// What kind of failure.
    pub fn kind(&self) -> FailureKind {
        self.failure.kind
    }

    /// Turns whatever went wrong into one of the fixed failures, keeping it as the cause.
    pub(crate) fn from_cause(cause: impl Into<Box<dyn StdError + Send + Sync>>) -> Self {
        let cause = cause.into();
        match cause.downcast::<Error>() {
            Ok(error) => *error,
            Err(cause) => Self {
                failure: classify(cause.as_ref()),
                source: Some(cause),
            },
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.failure.message)
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_deref()
            .map(|e| e as &(dyn StdError + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_mismatch_names_both_sides_and_which_to_update() {
        assert_eq!(
            Failure::version_mismatch(&[4]).message(),
            "This server speaks Skakel 4 and this app speaks Skakel 3. Update the app."
        );
        assert_eq!(
            Failure::version_mismatch(&[2]).message(),
            "This server speaks Skakel 2 and this app speaks Skakel 3. Update the server."
        );
        assert_eq!(
            Failure::version_mismatch(&[5, 4, 6, 4]).message(),
            "This server speaks Skakel 4, 5 and 6 and this app speaks Skakel 3. Update the app."
        );
        assert_eq!(
            Failure::version_mismatch(&[]).kind(),
            FailureKind::VersionMismatch
        );
    }

    #[test]
    fn every_kind_has_a_code_and_wording() {
        assert_eq!(
            Failure::of(FailureKind::CertificateMismatch).code(),
            "certificateMismatch"
        );
        assert_eq!(
            Failure::of(FailureKind::Unreachable).message(),
            "Could not reach the server. Check the address and that the server is running."
        );
    }

    #[test]
    fn an_error_keeps_its_cause_out_of_the_message() {
        let error = Error::from_cause(StatusError(500));

        assert_eq!(error.kind(), FailureKind::UnexpectedAnswer);
        assert_eq!(
            error.to_string(),
            "The server did not answer like a Skakel server."
        );
        assert_eq!(
            error.source().unwrap().to_string(),
            "The server answered 500."
        );
    }

    #[test]
    fn statuses_and_token_errors_map_to_their_kinds() {
        let cases: Vec<(Box<dyn StdError + Send + Sync>, FailureKind)> = vec![
            (Box::new(StatusError(401)), FailureKind::ClientUnknown),
            (Box::new(StatusError(429)), FailureKind::TooManyRequests),
            (Box::new(StatusError(404)), FailureKind::UnexpectedAnswer),
            (
                Box::new(TokenRequestError {
                    error: "invalid_client".into(),
                    status: 401,
                }),
                FailureKind::RejectedCredentials,
            ),
            (
                Box::new(TokenRequestError {
                    error: "x".into(),
                    status: 429,
                }),
                FailureKind::TooManyRequests,
            ),
            (
                Box::new(TokenRequestError {
                    error: "x".into(),
                    status: 400,
                }),
                FailureKind::UnexpectedAnswer,
            ),
            (
                Box::new(BadAnswer("x".into())),
                FailureKind::UnexpectedAnswer,
            ),
            (
                Box::new(io::Error::from(io::ErrorKind::ConnectionRefused)),
                FailureKind::Unreachable,
            ),
        ];

        for (cause, kind) in cases {
            let text = cause.to_string();
            assert_eq!(Error::from_cause(cause).kind(), kind, "{text}");
        }
    }

    #[test]
    fn a_certificate_error_inside_an_io_error_is_a_mismatch() {
        let inner = rustls::Error::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        );
        let error = Error::from_cause(io::Error::new(io::ErrorKind::InvalidData, inner));

        assert_eq!(error.kind(), FailureKind::CertificateMismatch);
        assert!(!is_unreachable(&error));
    }

    #[test]
    fn a_refused_connection_is_unreachable() {
        let error = Error::from_cause(io::Error::from(io::ErrorKind::ConnectionRefused));

        assert!(is_unreachable(&error));
        assert!(!is_unreachable(&Error::from_cause(StatusError(500))));
    }

    #[test]
    fn a_grpc_status_is_the_failure_its_reason_says() {
        use std::collections::HashMap;
        use tonic_types::{ErrorDetails, StatusExt};
        let with = |code, reason: &str, domain: &str| {
            Status::with_error_details(
                code,
                "words",
                ErrorDetails::with_error_info(reason, domain, HashMap::new()),
            )
        };
        let cases = [
            (
                with(Code::Unauthenticated, "TOKEN_REFUSED", "skakel"),
                FailureKind::ClientUnknown,
            ),
            (
                with(Code::Unauthenticated, "REVOKED", "skakel"),
                FailureKind::Revoked,
            ),
            (
                with(Code::Unauthenticated, "ROTATED", "skakel"),
                FailureKind::Rotated,
            ),
            (
                with(Code::Unavailable, "STOPPING", "skakel"),
                FailureKind::ServerStopping,
            ),
            (
                with(Code::Unavailable, "STOPPING", "someone.else"),
                FailureKind::ConnectionLost,
            ),
            (Status::unavailable("gone"), FailureKind::ConnectionLost),
            (Status::cancelled("gone"), FailureKind::ConnectionLost),
            (Status::unimplemented(""), FailureKind::UnexpectedAnswer),
        ];

        for (status, kind) in cases {
            let text = format!("{status:?}");
            assert_eq!(Error::from_cause(GrpcStatus(status)).kind(), kind, "{text}");
        }
    }

    #[test]
    fn an_error_made_of_an_error_stays_as_it_was() {
        let first = Error::of(FailureKind::Revoked);

        assert_eq!(Error::from_cause(first).kind(), FailureKind::Revoked);
    }
}
