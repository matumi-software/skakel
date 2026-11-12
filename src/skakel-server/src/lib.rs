//! Serve Skakel clients, protocol version 2: discovery answers, pairing approval, OAuth tokens,
//! revoking clients, the control channel and data streams over gRPC, and the certificate with its
//! handover. The wire format is in [`docs/protocol.md`](https://github.com/matumi-software/skakel/blob/main/docs/protocol.md)
//! and the parts are in [`docs/parts.md`](https://github.com/matumi-software/skakel/blob/main/docs/parts.md),
//! both at the root of the repository.
//!
//! An app builds a server with [`SkakelServerBuilder`], gives it a [`SkakelStore`] to keep its
//! state in, adds its own gRPC services ([`SkakelServerBuilder::grpc_service`]), stream types
//! ([`StreamHandler`]) and HTTPS routes, and starts it. Pairing needs a person: the app shows the requests it is told of (see
//! [`SkakelServer::subscribe`]) and calls [`Pairing::approve`] with the code the person typed.
//!
//! ```no_run
//! # async fn run() -> Result<(), skakel_server::ServerError> {
//! use skakel_server::{InMemoryStore, ServerEvent, SkakelServerBuilder};
//!
//! let server = SkakelServerBuilder::new("my-app", "1.0.0", InMemoryStore::new())
//!     .name("pi-lab")
//!     .listen("0.0.0.0:5240".parse().unwrap())
//!     .start()
//!     .await?;
//! println!("pinned to {}", server.fingerprint());
//!
//! // What happens on the server arrives as events, on a task of the app's own.
//! let mut events = server.subscribe();
//! tokio::spawn(async move {
//!     while let Some(event) = events.recv().await {
//!         if let ServerEvent::Pairing(overview) = event {
//!             for request in &overview.requests {
//!                 println!("{} wants to pair from {}", request.client_name, request.from);
//!             }
//!         }
//!     }
//! });
//! # Ok(())
//! # }
//! ```
//!
//! Everything runs on one TLS port, on a self-signed certificate the server makes itself: the
//! HTTPS calls (info, pairing, tokens, the app's routes) over HTTP/1.1 or HTTP/2, and gRPC
//! (Skakel's control and stream services and the app's own) over HTTP/2, told apart by content
//! type. Every gRPC call's token is checked before a service sees it, and the server ends a client's
//! running calls when it is revoked, its secret rotated or the server stops. Connections that carry
//! gRPC are pinged every 15 seconds and dropped after 30 without a word from the client.
//!
//! # Two ways to serve
//!
//! [`SkakelServerBuilder::start`], as above, gives Skakel the port: it binds the listener and runs
//! the accept loop, TLS and HTTP itself.
//!
//! An app that serves its own pages on the same port starts the server with
//! [`SkakelServerBuilder::start_mounted`] instead, which binds nothing, and serves Skakel on its
//! own listener. It takes three things from the server:
//!
//! - [`SkakelServer::service`], a tower service with Skakel's HTTPS endpoints and gRPC services,
//!   which the app mounts on its router, for example as the fallback service. Every request must
//!   carry the caller's address as an `axum::extract::ConnectInfo<SocketAddr>` in its extensions,
//!   because every per-address limit counts by it (see [`SkakelService`]).
//! - [`SkakelServer::tls_config`], the rustls settings for the app's TLS acceptor. They present the
//!   server's current certificate on every handshake, so a certificate handover works as it does on
//!   Skakel's own listener, and keep session resumption off.
//! - [`connection_builder`], a hyper-util connection builder with Skakel's HTTP/2 keep-alive and
//!   adaptive windows, and its HTTP/1.1 header timeout.
//!
//! The app's middleware must hand Skakel's answers on as they are (gRPC answers end in trailers),
//! so no compression or body rewriting in front of the service.
//!
//! The app's routes that take [`ClientPrincipal`] must still go to the server through
//! [`SkakelServerBuilder::routes`], which puts them in [`SkakelServer::service`]. On the app's own
//! router they never reach Skakel's state, so the extractor cannot check the token and answers 500.
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use axum::extract::ConnectInfo;
//! use hyper_util::rt::TokioIo;
//! use skakel_server::{InMemoryStore, SkakelServerBuilder, connection_builder};
//! use tokio_rustls::TlsAcceptor;
//! use tower_service::Service;
//!
//! let listener = tokio::net::TcpListener::bind("0.0.0.0:5240").await?;
//! let skakel = SkakelServerBuilder::new("my-app", "1.0.0", InMemoryStore::new())
//!     .start_mounted(listener.local_addr()?)
//!     .await?;
//! let app = axum::Router::new()
//!     .route("/", axum::routing::get(|| async { "the app's own page" }))
//!     .fallback_service(skakel.service());
//! let acceptor = TlsAcceptor::from(skakel.tls_config());
//! loop {
//!     let (tcp, remote) = listener.accept().await?;
//!     let (acceptor, app) = (acceptor.clone(), app.clone());
//!     tokio::spawn(async move {
//!         let Ok(tls) = acceptor.accept(tcp).await else { return };
//!         let service = hyper::service::service_fn(move |mut request: hyper::Request<_>| {
//!             // The caller's address, which Skakel's limits count by.
//!             request.extensions_mut().insert(ConnectInfo(remote));
//!             let mut app = app.clone();
//!             async move { app.call(request).await }
//!         });
//!         let _ = connection_builder()
//!             .serve_connection_with_upgrades(TokioIo::new(tls), service)
//!             .await;
//!     });
//! }
//! # }
//! ```
//!
//! The server logs nothing: what happens is told to the app as [`ServerEvent`]s. The one exception
//! is a route that takes [`ClientPrincipal`] but is not served by Skakel, where there is no server
//! to tell; the first such request logs an error through the `log` crate.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod control;
mod crypto;
mod discovery;
mod error;
mod events;
mod grpc;
mod http;
mod limits;
mod pairing;
mod server;
mod service;
mod sessions;
mod state;
mod store;
mod streams;
mod tokens;
mod util;

pub use crypto::CryptoError;
pub use error::{OptionProblem, ServerError, StateError};
pub use events::{ServerEvent, ServerEvents};
pub use http::ClientPrincipal;
pub use pairing::{Approval, Pairing, PairingDecision, PairingOverview, PairingRequest};
pub use server::{Certificates, Clients, SkakelServer, SkakelServerBuilder};
pub use service::{SkakelService, connection_builder};
pub use state::{CertificateSwitch, CertificatesView, ClientView, NewClient};
pub use store::{
    CertificateRecord, ClientRecord, FileStore, InMemoryStore, NextCertificateRecord, SkakelState,
    SkakelStore, StoreFuture,
};
pub use streams::{
    Accepted, StreamClosed, StreamEnd, StreamHandler, StreamMessage, StreamOpen, StreamRequest,
    StreamSession, StreamWriter,
};
pub use tokens::Principal;
