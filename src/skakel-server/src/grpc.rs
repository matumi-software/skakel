//! The gRPC side: refusals with their status and `ErrorInfo`, the token check in front of every
//! service, Skakel's and the app's, and ending an app's running calls when its client is revoked,
//! its secret rotated or the server stops.

use crate::streams::BoxFuture;
use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, HeaderValue, Request, Response};
use http_body::{Body as HttpBody, Frame, SizeHint};
use skakel_protocol::{ERROR_DOMAIN, Reason, is_grpc_content_type};
use tokio::sync::oneshot;
use tonic::body::Body;
use tonic::server::NamedService;
use tonic::{Code, Status};
use tonic_types::{ErrorDetails, StatusExt};
use tower_service::Service;

use crate::http::ClientPrincipal;
use crate::server::Shared;
use crate::sessions::SessionGuard;
use crate::tokens::Principal;

/// A status Skakel refuses or ends a call with: the reason's code, the message for a person, and an
/// `ErrorInfo` with the domain `skakel` and the reason.
pub(crate) fn refusal(reason: Reason, message: impl Into<String>) -> Status {
    Status::with_error_details(
        Code::from_i32(reason.code().number()),
        message,
        ErrorDetails::with_error_info(reason.as_str(), ERROR_DOMAIN, HashMap::new()),
    )
}

/// What a client is told for each reason the server ends its calls.
pub(crate) fn ending(reason: Reason) -> Status {
    let message = match reason {
        Reason::Revoked => "The server revoked this client. Pair with the server again.",
        Reason::Rotated => "The server gave this client a new secret. Pair with the server again.",
        Reason::Stopping => "The server is stopping.",
        Reason::TokenExpired => "The token this call was opened with has expired.",
        _ => "The server ended the call.",
    };
    refusal(reason, message)
}

/// The refusal for a call with no token, or one the server does not take.
pub(crate) fn token_refused() -> Status {
    refusal(
        Reason::TokenRefused,
        "Send a current bearer token. This one is missing or has expired, or the client was revoked or its secret rotated since it was issued.",
    )
}

/// The status a call ends with when reading the client's next message failed. tonic reports a
/// message over the limit as `OUT_OF_RANGE`; gRPC's other implementations, and the protocol, say
/// `RESOURCE_EXHAUSTED`, so that is what the client is told.
pub(crate) fn read_failed(status: Status) -> Status {
    if status.code() == Code::OutOfRange {
        Status::resource_exhausted(status.message())
    } else {
        status
    }
}

/// True for a request that is a gRPC call, by its content type.
pub(crate) fn is_grpc(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(is_grpc_content_type)
}

/// The principal of the bearer token in a call's `authorization` metadata.
fn authenticate(shared: &Shared, headers: &HeaderMap) -> Option<Principal> {
    shared
        .state
        .authenticate(crate::util::bearer_token(headers)?)
}

/// A gRPC service with Skakel's token check in front. A call without a current token is refused
/// with `TOKEN_REFUSED` before the service sees it; one with a token reaches it with a
/// [`ClientPrincipal`] in its extensions. With `track`, the call is ended with `REVOKED`, `ROTATED`
/// or `STOPPING` when that happens while it runs; Skakel's own services end their calls
/// themselves, so they are not tracked here.
#[derive(Clone)]
pub(crate) struct Guarded<S> {
    inner: S,
    shared: Arc<Shared>,
    track: bool,
}

impl<S> Guarded<S> {
    pub(crate) fn new(inner: S, shared: Arc<Shared>, track: bool) -> Self {
        Self {
            inner,
            shared,
            track,
        }
    }
}

impl<S: NamedService> NamedService for Guarded<S> {
    const NAME: &'static str = S::NAME;
}

impl<S> Service<Request<Body>> for Guarded<S>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<Response<Body>, Infallible>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        let Some(principal) = authenticate(&self.shared, request.headers()) else {
            return Box::pin(async { Ok(token_refused().into_http()) });
        };
        let session = self.track.then(|| {
            self.shared
                .sessions
                .add_call(&principal.client_id, principal.generation)
        });
        request.extensions_mut().insert(ClientPrincipal(principal));
        // The service that was made ready takes the call; a clone stays for the next one.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let answer = inner.call(request);
        Box::pin(async move {
            let Some((guard, mut ended)) = session else {
                let Ok(mut response) = answer.await;
                out_of_range_is_resource_exhausted(&mut response);
                return Ok(response);
            };
            tokio::select! {
                answer = answer => {
                    let Ok(response) = answer;
                    let (parts, body) = response.into_parts();
                    let body = Ending {
                        inner: body,
                        ended: Some(ended),
                        done: false,
                        _guard: guard,
                    };
                    Ok(Response::from_parts(parts, Body::new(body)))
                }
                reason = &mut ended => {
                    let reason = reason.unwrap_or(Reason::Stopping);
                    Ok(ending(reason).into_http())
                }
            }
        })
    }
}

/// A call to one of Skakel's own services that tonic refused for a message over the limit before
/// the service saw it comes back with `OUT_OF_RANGE` in its headers. Skakel's services never answer
/// that code, and the protocol says `RESOURCE_EXHAUSTED`, so it is told as that. The streaming
/// calls map the code themselves when they read, so this is the one unary call, `Hello`.
fn out_of_range_is_resource_exhausted(response: &mut Response<Body>) {
    let out_of_range = (Code::OutOfRange as i32).to_string();
    if response
        .headers()
        .get("grpc-status")
        .is_some_and(|status| status.as_bytes() == out_of_range.as_bytes())
    {
        response.headers_mut().insert(
            "grpc-status",
            HeaderValue::from(Code::ResourceExhausted as i32),
        );
    }
}

/// An app call's answer, which ends with the reason's status when its client is revoked, its
/// secret rotated or the server stops, and lets go of the call once it is over.
struct Ending {
    inner: Body,
    ended: Option<oneshot::Receiver<Reason>>,
    done: bool,
    _guard: SessionGuard,
}

impl HttpBody for Ending {
    type Data = <Body as HttpBody>::Data;
    type Error = <Body as HttpBody>::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.done {
            return Poll::Ready(None);
        }
        if let Some(ended) = self.ended.as_mut()
            && let Poll::Ready(reason) = Pin::new(ended).poll(cx)
        {
            self.ended = None;
            if let Ok(reason) = reason {
                self.done = true;
                let mut trailers = HeaderMap::new();
                // A status always fits in headers; one that would not is left out, which ends the
                // call without a status, as a lost connection does.
                let _ = ending(reason).add_header(&mut trailers);
                return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
            }
        }
        let frame = ready!(Pin::new(&mut self.inner).poll_frame(cx));
        match &frame {
            None => self.done = true,
            Some(Ok(frame)) if frame.is_trailers() => self.done = true,
            Some(Err(_)) => self.done = true,
            Some(Ok(_)) => {}
        }
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        self.done
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_carries_the_code_the_message_and_the_reason_in_the_skakel_domain() {
        let status = refusal(Reason::InUse, "bench-2 holds busy.");

        assert_eq!(status.code(), Code::FailedPrecondition);
        assert_eq!(status.message(), "bench-2 holds busy.");
        let info = status.get_details_error_info().expect("an ErrorInfo");
        assert_eq!(info.reason, "IN_USE");
        assert_eq!(info.domain, "skakel");
        let details = <tonic_types::pb::Status as prost::Message>::decode(status.details())
            .expect("a google.rpc.Status");
        assert_eq!(details.code, Code::FailedPrecondition as i32);
        assert_eq!(details.message, "bench-2 holds busy.");
        assert_eq!(details.details.len(), 1);
    }

    #[test]
    fn each_ending_has_its_reasons_code() {
        assert_eq!(ending(Reason::Revoked).code(), Code::Unauthenticated);
        assert_eq!(ending(Reason::Rotated).code(), Code::Unauthenticated);
        assert_eq!(ending(Reason::TokenExpired).code(), Code::Unauthenticated);
        assert_eq!(ending(Reason::Stopping).code(), Code::Unavailable);
        assert_eq!(token_refused().code(), Code::Unauthenticated);
    }

    #[test]
    fn a_grpc_call_is_told_by_its_content_type() {
        let mut headers = HeaderMap::new();
        assert!(!is_grpc(&headers));
        headers.insert(CONTENT_TYPE, "application/grpc+proto".parse().unwrap());
        assert!(is_grpc(&headers));
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        assert!(!is_grpc(&headers));
    }
}
