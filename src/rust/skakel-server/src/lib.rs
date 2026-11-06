//! Serve Skakel clients: discovery answers, pairing approval, OAuth tokens, revoking clients, the
//! control hub, data streams and the certificate with its handover. The wire format is in
//! `docs/protocol.md` at the repository root and the parts are in `docs/parts.md`; this crate is
//! the Rust counterpart of the .NET `Skakel.Server`.
//!
//! An app builds a server with [`SkakelServerBuilder`], gives it a [`SkakelStore`] to keep its
//! state in, adds its own hubs ([`HubHandler`]), stream types ([`StreamHandler`]) and routes, and
//! starts it. Pairing needs a person: the app shows the requests it is told of (see
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
//! The server serves HTTPS only, on a self-signed certificate it makes itself, and logs nothing:
//! what happens is told to the app as [`ServerEvent`]s.

mod crypto;
mod discovery;
mod error;
mod events;
mod http;
mod hub;
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
pub use hub::{HubCall, HubConnection, HubError, HubHandle, HubHandler};
pub use pairing::{Approval, Pairing, PairingDecision, PairingOverview, PairingRequest};
pub use server::{Clients, Keys, SkakelServer, SkakelServerBuilder};
pub use state::{CertificateSwitch, ClientView, KeysView, NewClient};
pub use store::{
    CertificateRecord, ClientRecord, FileStore, InMemoryStore, KeyRecord, NextCertificateRecord,
    SkakelState, SkakelStore, StoreFuture,
};
pub use streams::{
    BoxFuture, StreamClosed, StreamHandler, StreamMessage, StreamOpen, StreamRequest,
    StreamSession, StreamWriter,
};
pub use util::clean_client_name;
