//! What went wrong talking to a server, as a fixed set of kinds with fixed wording. The detail of a
//! failure goes to the log and stays on [`Error::source`], never into the message, so the wording
//! cannot be used to probe addresses and ports.

use std::error::Error as StdError;
use std::fmt;
use std::io;

use skakel_protocol::VERSIONS;

/// What went wrong. An app shows [`Failure::message`] and acts on the kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    pub fn of(kind: FailureKind) -> Self {
        Self {
            kind,
            message: kind.message().to_owned(),
        }
    }

    /// The server speaks none of this client's protocol versions, worded with both sides' versions
    /// and which one to update, such as "This server speaks Skakel 2 and this app speaks Skakel 1.
    /// Update the app."
    pub fn version_mismatch(server_versions: &[i32]) -> Self {
        let Some(highest) = server_versions.iter().max() else {
            return Self::of(FailureKind::VersionMismatch);
        };
        let ours: Vec<i32> = VERSIONS.iter().map(|v| *v as i32).collect();
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
                list(&ours)
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
fn list(versions: &[i32]) -> String {
    let mut words: Vec<i32> = versions.to_vec();
    words.sort_unstable();
    words.dedup();
    let words: Vec<String> = words.iter().map(i32::to_string).collect();
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
    pub fn new(failure: Failure) -> Self {
        Self {
            failure,
            source: None,
        }
    }

    /// A failure and what caused it.
    pub fn with_source(
        failure: Failure,
        source: impl Into<Box<dyn StdError + Send + Sync>>,
    ) -> Self {
        Self {
            failure,
            source: Some(source.into()),
        }
    }

    /// An error of this kind with its fixed wording.
    pub fn of(kind: FailureKind) -> Self {
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

/// The causes of an error, the error first. An `io::Error` also gives what it wraps, which its own
/// `source` skips.
fn chain<'a>(error: &'a (dyn StdError + 'static)) -> Vec<&'a (dyn StdError + 'static)> {
    let mut all = Vec::new();
    let mut next = Some(error);
    while let Some(e) = next {
        all.push(e);
        if let Some(inner) = e
            .downcast_ref::<io::Error>()
            .and_then(io::Error::get_ref)
            .map(|inner| inner as &(dyn StdError + 'static))
        {
            all.extend(chain(inner));
        }
        next = e.source();
    }
    all
}

fn classify(error: &(dyn StdError + 'static)) -> Failure {
    let causes = chain(error);
    if let Some(ours) = causes.iter().find_map(|e| e.downcast_ref::<Error>()) {
        return ours.failure.clone();
    }
    // A handshake that failed on the certificate is a certificate we do not trust, wherever it
    // surfaced.
    if causes.iter().any(|e| {
        matches!(
            e.downcast_ref::<rustls::Error>(),
            Some(rustls::Error::InvalidCertificate(_))
        )
    }) {
        return Failure::of(FailureKind::CertificateMismatch);
    }
    for e in &causes {
        if let Some(token) = e.downcast_ref::<TokenRequestError>() {
            return Failure::of(match (token.error.as_str(), token.status) {
                ("invalid_client", _) => FailureKind::RejectedCredentials,
                (_, 429) => FailureKind::TooManyRequests,
                _ => FailureKind::UnexpectedAnswer,
            });
        }
        if let Some(StatusError(status)) = e.downcast_ref::<StatusError>() {
            return Failure::of(match status {
                429 => FailureKind::TooManyRequests,
                401 => FailureKind::ClientUnknown,
                _ => FailureKind::UnexpectedAnswer,
            });
        }
        if e.is::<BadAnswer>() || e.is::<serde_json::Error>() {
            return Failure::of(FailureKind::UnexpectedAnswer);
        }
    }
    Failure::of(FailureKind::Unreachable)
}

/// True when nothing answered at the server's address: the connection was refused or timed out,
/// there was no route, or the name no longer resolves. A server that answered, with a certificate
/// that does not match or by refusing the credentials, is not unreachable.
pub(crate) fn is_unreachable(error: &Error) -> bool {
    let Some(source) = error.source() else {
        return error.kind() == FailureKind::Unreachable;
    };
    if error.kind() != FailureKind::Unreachable {
        return false;
    }
    chain(source).iter().any(|e| {
        if let Some(reqwest) = e.downcast_ref::<reqwest::Error>() {
            return reqwest.is_connect() || reqwest.is_timeout();
        }
        if let Some(io) = e.downcast_ref::<io::Error>() {
            return matches!(
                io.kind(),
                io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::HostUnreachable
                    | io::ErrorKind::NetworkUnreachable
                    | io::ErrorKind::NotFound
            ) || io.raw_os_error().is_some();
        }
        e.is::<tokio::time::error::Elapsed>()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_mismatch_names_both_sides_and_which_to_update() {
        assert_eq!(
            Failure::version_mismatch(&[3]).message(),
            "This server speaks Skakel 3 and this app speaks Skakel 2. Update the app."
        );
        assert_eq!(
            Failure::version_mismatch(&[1]).message(),
            "This server speaks Skakel 1 and this app speaks Skakel 2. Update the server."
        );
        assert_eq!(
            Failure::version_mismatch(&[4, 3, 5, 3]).message(),
            "This server speaks Skakel 3, 4 and 5 and this app speaks Skakel 2. Update the app."
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
    fn an_error_made_of_an_error_stays_as_it_was() {
        let first = Error::of(FailureKind::Revoked);

        assert_eq!(Error::from_cause(first).kind(), FailureKind::Revoked);
    }
}
