//! Reach Skakel servers, protocol version 2: find them, pair, get tokens, pin the certificate, keep
//! the control channel up, call the app's own gRPC services and open data streams. See
//! `docs/protocol.md` and `docs/parts.md` at the repository root.
//!
//! The pieces:
//!
//! - [`Browser`] finds servers on the local network.
//! - [`read_info`], [`pick_version`] and [`require_version`] read a server's info and choose the
//!   protocol version to speak.
//! - [`PairingClient`] pairs with a server by the six-digit code a person compares.
//! - [`Link`] is the client's link to one server: pinned HTTPS and gRPC, tokens, the control channel
//!   with its renewal and the certificate handover, following the server when it moves, the app's
//!   own gRPC calls ([`Link::channel`]) and HTTPS requests, and data streams, each on a connection of
//!   its own. [`Link::open_serial`] gives a [`SerialConnection`].
//! - [`Pins`] and [`Credentials`] are what an app keeps for each server it is paired with.
//! - [`Error`] carries a [`Failure`], a fixed set of kinds with fixed wording an app shows. The
//!   detail goes to the log through the [`log`] crate and to
//!   [`Error::source`](std::error::Error::source), never into the message.
//!
//! # Changes
//!
//! Two shapes carry every change to an app. A [`StateWatch`] holds the latest value of something and
//! says when it changes: [`Link::watch_status`], [`Link::watch_address`], [`Link::watch_pins`],
//! [`Browser::watch`]. An [`Events`] receiver has what happened, in order: [`Link::events`],
//! [`SerialConnection::events`]. Neither runs the app's code, so a slow subscriber never holds a
//! link up. The one thing the app must answer is the certificate handover: give the link a
//! [`PinStore`] with [`Link::set_pin_store`], and it tells the server it has the next certificate
//! only once the store has saved it.
//!
//! # Example
//!
//! ```no_run
//! use skakel_client::{ClientOptions, Credentials, Link, LinkEvent, LinkState, Pins, Url};
//!
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! // What the app saved when it paired: the address, the pins and the credentials.
//! let fingerprint = "ab".repeat(32);
//! let link = Link::new(
//!     &Url::parse("https://192.168.1.20:5240/")?,
//!     Pins::new(&fingerprint)?,
//!     Credentials::new("client-id", "client-secret"),
//!     ClientOptions::default(),
//! )?;
//! link.set_pin_store(|pins: Pins| async move {
//!     // Keep the pins where the app keeps its settings.
//!     let _ = pins;
//!     Ok::<(), std::io::Error>(())
//! });
//! let mut events = link.events();
//! link.start();
//! while let Ok(event) = events.recv().await {
//!     if let LinkEvent::Status(status) = event {
//!         if status.state == LinkState::Connected {
//!             break;
//!         }
//!     }
//! }
//! let hello = link.hello().await?;
//! println!("{} says hello to {}", hello.server, hello.client_id);
//! link.stop().await;
//! # Ok(())
//! # }
//! ```
//!
//! # Trust
//!
//! A Skakel server's certificate is self-signed. Every connection this crate makes, to any address,
//! HTTPS or gRPC, checks the SHA-256 fingerprint of the certificate against the [`Pins`] and trusts
//! nothing else: not a system root, not a name. The pins are read at each handshake, so a handover
//! the link learned about takes effect for the next connection. gRPC runs only on connections where
//! ALPN chose `h2`, and every one of them is pinged after 15 quiet seconds and dropped when it has
//! said nothing for 30.
//!
//! # Runtime
//!
//! Everything is async on tokio, and says so: a [`Link`], a [`Browser`] and a pairing request start
//! tasks and need a running tokio runtime, and [`StreamIo`] implements tokio's `AsyncRead` and
//! `AsyncWrite`. There is no runtime-agnostic mode.
//!
//! # What an app depends on
//!
//! The app's own gRPC services are reached through [`LinkChannel`], a `tower` service over tonic's
//! request and body types, so an app that builds tonic clients on it uses the same `tonic` version as
//! this crate (0.14) and names it in its own `Cargo.toml`. Nothing else of tonic, and nothing of
//! hyper, rustls or reqwest, appears in the API. [`Url`], [`Method`] and [`StatusCode`] are the
//! `url` and `http` crates' types.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod browser;
mod clock;
mod events;
mod failure;
mod grpc;
mod http;
mod info;
mod link;
mod moves;
mod options;
mod pairing;
mod pins;
mod request;
mod serial;
mod status;
mod stream_io;
mod streams;
mod tokens;

pub use ::http::{Method, StatusCode};
pub use browser::{Browser, BrowserOptions, DiscoveredServer};
pub use clock::{Clock, Sleep, SystemClock};
pub use events::{Events, EventsError, StateWatch};
pub use failure::{Error, Failure, FailureKind, Result};
pub use info::{pick_version, read_info, require_version};
pub use link::{
    Link, LinkChannel, LinkEvent, LinkState, LinkStatus, PinStore, SaveFuture, StoreError,
};
pub use options::ClientOptions;
pub use pairing::{MAX_WAIT, PairingClient, PairingError};
pub use pins::{Credentials, InvalidFingerprint, Pins};
pub use request::{RequestBuilder, Response};
pub use serial::{SerialChange, SerialConnection, SerialEvent};
pub use status::GrpcCode;
pub use stream_io::StreamIo;
pub use streams::{
    Frame, OpenResult, StreamClose, StreamCloseReason, StreamConnection, StreamRefusal,
    StreamRefusalReason,
};
pub use url::Url;

/// Skakel's own types the client's API is made of, so an app needs only this crate.
pub use prost::bytes::Bytes;
pub use skakel_protocol::{SkakelApp, SkakelHello, SkakelInfo};
pub use skakel_serial::{
    DataBits, ErrorCode, FlowControl, LineSettings, ModemStatus, Parity, StopBits,
};
