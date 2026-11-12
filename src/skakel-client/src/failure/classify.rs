//! Turning whatever went wrong into one of the fixed failures.

use super::*;

/// The failure a gRPC status means: the Skakel reason it carries, or for one with no reason, a lost
/// connection or an answer the client cannot use.
pub(super) fn failure_of_status(status: &Status) -> FailureKind {
    match crate::grpc::reason_of(status) {
        Some(Reason::TokenRefused) => FailureKind::ClientUnknown,
        Some(Reason::Revoked) => FailureKind::Revoked,
        Some(Reason::Rotated) => FailureKind::Rotated,
        Some(Reason::Stopping) => FailureKind::ServerStopping,
        Some(Reason::TokenExpired) => FailureKind::ConnectionLost,
        Some(_) => FailureKind::UnexpectedAnswer,
        None => match status.code() {
            Code::Unavailable | Code::Cancelled | Code::Unknown | Code::DeadlineExceeded => {
                FailureKind::ConnectionLost
            }
            _ => FailureKind::UnexpectedAnswer,
        },
    }
}

/// The causes of an error, the error first. An `io::Error` also gives what it wraps, which its own
/// `source` skips.
pub(super) fn chain<'a>(error: &'a (dyn StdError + 'static)) -> Vec<&'a (dyn StdError + 'static)> {
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

pub(super) fn classify(error: &(dyn StdError + 'static)) -> Failure {
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
        if let Some(GrpcStatus(status)) = e.downcast_ref::<GrpcStatus>() {
            return Failure::of(failure_of_status(status));
        }
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
