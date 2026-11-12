//! Skakel's HTTPS endpoints and gRPC services as one tower service, which the server's own
//! listener serves and which an app can mount on a listener of its own, and the connection
//! settings either listener applies.

use crate::streams::BoxFuture;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::BoxError;
use axum::Router;
use axum::body::Bytes;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use hyper_util::server::conn::auto;
use skakel_wire::{KEEP_ALIVE_INTERVAL, KEEP_ALIVE_TIMEOUT, Reason};
use tokio::sync::watch;
use tower_service::Service;

use crate::grpc::{ending, is_grpc};
use crate::http::problem;

/// How long a client has to send the headers of a request.
const HEADER_TIMEOUT: Duration = Duration::from_secs(30);

/// The HTTPS routes and the gRPC services, which share the port and its connections.
#[derive(Clone)]
pub(crate) struct Routers {
    pub https: Router,
    pub grpc: Router,
}

/// Skakel's HTTPS endpoints (info, pairing, tokens and the app's routes given to the builder) and
/// its gRPC services (Skakel's control and stream services and the app's, each behind the token
/// check), as one tower service. Get it from [`SkakelServer::service`](crate::SkakelServer::service).
///
/// An app that serves Skakel on a listener of its own mounts it on its server, for example as an
/// axum router's fallback service, or by handing it every gRPC call (by content type), every path
/// under `/skakel/` and the paths of the routes it gave the builder. The service routes a request
/// to the gRPC services when its content type is gRPC and to the HTTPS endpoints otherwise.
///
/// Every request must carry the caller's address as an `axum::extract::ConnectInfo<SocketAddr>`
/// (axum 0.8) in its extensions. axum's `into_make_service_with_connect_info::<SocketAddr>()`
/// puts it there, and an app with its own accept loop inserts it with the address `accept` gave.
/// Every per-address limit counts by it: token requests and pairing calls a minute, and pairing
/// requests opened and open at once. A request without it is refused, with 500 on HTTPS and
/// `INTERNAL` on gRPC, rather than counting every caller together.
///
/// Once the server is shut down or dropped, the service answers 503 on HTTPS and `STOPPING` on
/// gRPC.
#[derive(Clone)]
pub struct SkakelService {
    routers: Routers,
    stopped: watch::Receiver<bool>,
}

impl SkakelService {
    pub(crate) fn new(routers: Routers, stopped: watch::Receiver<bool>) -> Self {
        Self { routers, stopped }
    }
}

impl std::fmt::Debug for SkakelService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SkakelService")
    }
}

impl<B> Service<Request<B>> for SkakelService
where
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    type Response = Response;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<Response, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let grpc = is_grpc(request.headers());
        if *self.stopped.borrow() {
            let answer = if grpc {
                ending(Reason::Stopping).into_http()
            } else {
                problem(StatusCode::SERVICE_UNAVAILABLE, "The server is stopping.")
            };
            return Box::pin(async move { Ok(answer) });
        }
        if request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .is_none()
        {
            let detail = "The app serving Skakel did not give the caller's address, which Skakel needs for its limits.";
            let answer = if grpc {
                tonic::Status::internal(detail).into_http()
            } else {
                problem(StatusCode::INTERNAL_SERVER_ERROR, detail)
            };
            return Box::pin(async move { Ok(answer) });
        }
        let mut router = if grpc {
            self.routers.grpc.clone()
        } else {
            self.routers.https.clone()
        };
        Box::pin(async move { router.call(request).await })
    }
}

/// A hyper-util connection builder with the settings Skakel's own listener uses, for an app that
/// serves Skakel on a listener of its own. Serve each TLS connection with
/// `serve_connection_with_upgrades`.
///
/// - HTTP/2 keep-alive: a PING after 15 seconds without a frame from the client, and the
///   connection is dropped when that PING has no answer 15 seconds later, 30 seconds of silence in
///   all, as the protocol says. Pings from the client are answered at any rate.
/// - HTTP/2 adaptive flow-control windows, so a stream's window grows with the link beyond HTTP/2's
///   64 KiB start, which would hold a stream to 64 KiB per round trip.
/// - HTTP/1.1: 30 seconds to send a request's headers.
///
/// An app that builds its own connections applies the same.
pub fn connection_builder() -> auto::Builder<TokioExecutor> {
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(KEEP_ALIVE_INTERVAL)
        .keep_alive_timeout(KEEP_ALIVE_TIMEOUT - KEEP_ALIVE_INTERVAL)
        .adaptive_window(true);
    builder
}
