//! gRPC connections to a server: one TLS connection pinned to the server's certificates, with ALPN
//! `h2`, carrying HTTP/2 and nothing else. The link holds one for its control channel, each stream
//! opens one of its own, and a hello opens one for itself.
//!
//! A connection is one TCP connection. When it drops it is gone: nothing here dials again behind
//! the caller's back, so the link decides when to connect again and keeps to its once a second.
//! Both ends ping: this one sends an HTTP/2 PING once it has heard nothing for 15 seconds, with
//! calls running or not, and drops the connection when 15 more seconds pass without an answer.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http_body_util::BodyExt;
use hyper::client::conn::http2::{Builder, SendRequest};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use skakel_wire::{KEEP_ALIVE_INTERVAL, KEEP_ALIVE_TIMEOUT, Reason};
use tokio::sync::watch;
use tonic::body::Body;
use tonic::codegen::http;
use tonic::{Code, Status};
use tonic_types::StatusExt;
use url::Host;
use url::Url;

use crate::failure::{Error, FailureKind, GrpcStatus, bad_answer};
use crate::http::{PinsFn, Presented, connect_tls, last_presented, presented, tls_config};

/// One HTTP/2 connection to a server, pinned. Dropping the last handle closes it.
#[derive(Clone)]
pub(crate) struct Connection {
    send: SendRequest<Body>,
    authority: Arc<str>,
    presented: Option<String>,
    closed: watch::Receiver<bool>,
    _driver: Arc<Driver>,
}

/// Stops the task that drives the connection when the last handle goes.
struct Driver(tokio::task::AbortHandle);

impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("authority", &self.authority)
            .finish_non_exhaustive()
    }
}

impl Connection {
    /// Opens a connection to `address`: TCP within ten seconds, then TLS pinned to `pins` with ALPN
    /// `h2`, then HTTP/2, within `timeout` in all. A server that picks anything but `h2` did not
    /// answer like a Skakel server.
    pub(crate) async fn open(
        address: &Url,
        pins: PinsFn,
        timeout: Duration,
    ) -> Result<Self, Error> {
        let port = address.port_or_known_default().unwrap_or(443);
        let authority: Arc<str> = match address.host() {
            Some(Host::Ipv6(ip)) => format!("[{ip}]:{port}"),
            Some(host) => format!("{host}:{port}"),
            None => return Err(Error::of(FailureKind::Unreachable)),
        }
        .into();
        let presented_by: Presented = presented();
        let opening = async {
            let mut config = tls_config(pins, Some(presented_by.clone()));
            config.alpn_protocols = vec![b"h2".to_vec()];
            // A resumed session shows no certificate, and the link proves a certificate by what a
            // new connection presents.
            config.resumption = rustls::client::Resumption::disabled();
            let tls = connect_tls(address, Arc::new(config)).await?;
            if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
                return Err(bad_answer(
                    "The server did not choose HTTP/2 for a connection that offered only h2.",
                ));
            }

            let (send, connection) = Builder::new(TokioExecutor::new())
                .timer(TokioTimer::new())
                .keep_alive_interval(KEEP_ALIVE_INTERVAL)
                .keep_alive_timeout(KEEP_ALIVE_TIMEOUT - KEEP_ALIVE_INTERVAL)
                .keep_alive_while_idle(true)
                .adaptive_window(true)
                .handshake(TokioIo::new(tls))
                .await
                .map_err(Error::from_cause)?;
            Ok::<_, Error>((send, connection))
        };
        let (send, connection) = tokio::time::timeout(timeout, opening)
            .await
            .map_err(Error::from_cause)??;
        let (closed_tx, closed) = watch::channel(false);
        let driver = tokio::spawn(async move {
            let _ = connection.await;
            closed_tx.send_replace(true);
        });
        Ok(Self {
            send,
            authority,
            presented: last_presented(&presented_by),
            closed,
            _driver: Arc::new(Driver(driver.abort_handle())),
        })
    }

    /// The fingerprint of the certificate this connection's handshake presented.
    pub(crate) fn presented(&self) -> Option<&str> {
        self.presented.as_deref()
    }

    /// Resolves once the connection has dropped or stopped answering pings.
    pub(crate) async fn closed(&self) {
        let mut closed = self.closed.clone();
        let _ = closed.wait_for(|closed| *closed).await;
    }

    /// True once the connection has dropped.
    pub(crate) fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }

    /// A handle to make calls on this connection with, for tonic's generated clients.
    pub(crate) fn service(&self) -> ConnectionService {
        ConnectionService {
            send: self.send.clone(),
            authority: self.authority.clone(),
        }
    }
}

/// Makes calls on one connection: each request gets the server's scheme and authority, and a
/// connection that fails becomes `UNAVAILABLE`, as gRPC calls a lost connection.
#[derive(Clone)]
pub(crate) struct ConnectionService {
    send: SendRequest<Body>,
    authority: Arc<str>,
}

pub(crate) type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// What a lost connection is to a call: `UNAVAILABLE`, with no Skakel reason.
pub(crate) fn lost(error: impl std::fmt::Display) -> Status {
    Status::unavailable(format!("The connection to the server was lost: {error}"))
}

impl tower_service::Service<http::Request<Body>> for ConnectionService {
    type Response = http::Response<Body>;
    type Error = Status;
    type Future = BoxFuture<Result<Self::Response, Status>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Status>> {
        self.send.poll_ready(cx).map_err(lost)
    }

    fn call(&mut self, mut request: http::Request<Body>) -> Self::Future {
        let path = request
            .uri()
            .path_and_query()
            .map_or("/", |p| p.as_str())
            .to_owned();
        match format!("https://{}{path}", self.authority).parse() {
            Ok(uri) => *request.uri_mut() = uri,
            Err(_) => {
                return Box::pin(async { Err(Status::internal("The call's path is not valid.")) });
            }
        }
        let sending = self.send.send_request(request);
        Box::pin(async move {
            let response = sending.await.map_err(lost)?;
            Ok(response.map(|body| Body::new(body.map_err(lost))))
        })
    }
}

/// The Skakel reason in a status's `ErrorInfo`, when it has one in the domain `skakel`.
pub(crate) fn reason_of(status: &Status) -> Option<Reason> {
    let info = status.get_details_error_info()?;
    (info.domain == skakel_wire::ERROR_DOMAIN)
        .then(|| Reason::parse(&info.reason))
        .flatten()
}

/// The domain and reason of a status's `ErrorInfo`, whatever its domain.
pub(crate) fn error_info_of(status: &Status) -> Option<(String, String)> {
    status
        .get_details_error_info()
        .map(|info| (info.domain, info.reason))
}

/// True for a status that means the token was refused: `UNAUTHENTICATED` with `TOKEN_REFUSED`.
pub(crate) fn is_token_refused(status: &Status) -> bool {
    status.code() == Code::Unauthenticated && reason_of(status) == Some(Reason::TokenRefused)
}

/// A call that failed with `status`, as the client's error.
pub(crate) fn call_failed(status: Status) -> Error {
    Error::from_cause(GrpcStatus(status))
}
