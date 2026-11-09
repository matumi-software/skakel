//! Serve Skakel clients, protocol version 2: discovery answers, pairing approval, OAuth tokens,
//! revoking clients, the control channel and data streams over gRPC, and the certificate with its
//! handover. The wire format is in `docs/protocol.md` at the repository root and the parts are in
//! `docs/parts.md`.
//!
//! An app builds a server with [`SkakelServerBuilder`], gives it a [`SkakelStore`] to keep its
//! state in, adds its own gRPC services ([`SkakelServerBuilder::grpc_service`]), stream types
//! ([`StreamHandler`]) and HTTPS routes, and starts it. Pairing needs a person: the app shows the requests it is told of (see
//! [`SkakelServerBuilder::on_pairing`]) and calls [`Pairing::approve`] with the code the person
//! typed.
//!
//! ```no_run
//! # async fn run() -> Result<(), skakel_server::ServerError> {
//! use skakel_server::{InMemoryStore, SkakelServerBuilder};
//!
//! let server = SkakelServerBuilder::new("my-app", "1.0.0", InMemoryStore::new())
//!     .name("pi-lab")
//!     .listen("0.0.0.0:5240".parse().unwrap())
//!     .on_pairing(|overview| {
//!         for request in &overview.requests {
//!             println!("{} wants to pair from {}", request.client_name, request.from);
//!         }
//!     })
//!     .start()
//!     .await?;
//! println!("pinned to {}", server.fingerprint());
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
//! The server logs nothing: what happens is told to the app as [`ServerEvent`]s.

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
mod sessions;
mod state;
mod store;
mod streams;
mod util;

pub use crypto::{ISSUER, Principal};
pub use error::ServerError;
pub use events::ServerEvent;
pub use http::ClientPrincipal;
pub use pairing::{Approval, Pairing, PairingDecision, PairingOverview, PairingRequest};
pub use server::{Clients, Keys, SkakelServer, SkakelServerBuilder};
pub use state::{CertificateSwitch, ClientView, KeysView, NewClient};
pub use store::{
    CertificateRecord, ClientRecord, FileStore, InMemoryStore, KeyRecord, NextCertificateRecord,
    SkakelState, SkakelStore, StoreFuture,
};
pub use streams::{
    BoxFuture, StreamClosed, StreamEnd, StreamHandler, StreamMessage, StreamOpen, StreamRequest,
    StreamSession, StreamWriter,
};
pub use util::clean_client_name;
