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
//! Everything is async on tokio. A [`Link`] and a [`Browser`] start tasks, so they are used from
//! inside a tokio runtime.

mod browser;
mod clock;
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
mod streams;
mod tokens;

pub use ::http::{Method, StatusCode};
pub use browser::{Browser, BrowserOptions, DiscoveredServer};
pub use clock::{Clock, Sleep, SystemClock};
pub use failure::{Error, Failure, FailureKind, Result};
pub use info::{pick_version, read_info, require_version};
pub use link::{HandlerError, Link, LinkChannel, LinkState, LinkStatus};
pub use options::ClientOptions;
pub use pairing::{MAX_WAIT, PairingClient, PairingError};
pub use pins::{Credentials, InvalidFingerprint, Pins};
pub use request::{RequestBuilder, Response};
pub use serial::{SerialChange, SerialConnection, SerialEvent};
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
/// The gRPC library [`LinkChannel`] and the stream statuses come from, so an app builds its
/// generated clients on the same version.
pub use tonic;
