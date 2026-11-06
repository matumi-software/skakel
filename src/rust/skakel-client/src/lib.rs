//! Reach Skakel servers: find them, pair, get tokens, pin the certificate, follow the control hub
//! and open data streams. See `docs/protocol.md` and `docs/parts.md` at the repository root; this is
//! the Rust side of `Skakel.Client`, with the same features.
//!
//! The pieces, each the counterpart of the .NET type of the same job:
//!
//! - [`Browser`] finds servers on the local network ([`SkakelBrowser`] in .NET).
//! - [`read_info`], [`pick_version`] and [`require_version`] read a server's info and choose the
//!   protocol version to speak.
//! - [`PairingClient`] pairs with a server by the six-digit code a person compares.
//! - [`Link`] is the client's link to one server: pinned HTTP, tokens, the control hub with
//!   certificate handover, following the server when it moves, requests to the app's own endpoints
//!   and data streams. [`Link::open_serial`] gives a [`SerialConnection`].
//! - [`Pins`] and [`Credentials`] are what an app keeps for each server it is paired with.
//! - [`Error`] carries a [`Failure`], a fixed set of kinds with fixed wording an app shows. The
//!   detail goes to the log through the [`log`] crate and to [`Error::source`], never into the
//!   message.
//!
//! # Trust
//!
//! A Skakel server's certificate is self-signed. Every connection this crate makes, to any address,
//! checks the SHA-256 fingerprint of the certificate against the [`Pins`] and trusts nothing else:
//! not a system root, not a name. The pins are read at each handshake, so a handover the link
//! learned about takes effect for the next connection.
//!
//! # Runtime
//!
//! Everything is async on tokio. A [`Link`] and a [`Browser`] start tasks, so they are used from
//! inside a tokio runtime.

mod browser;
mod clock;
mod failure;
mod http;
mod hub;
mod info;
mod link;
mod moves;
mod options;
mod pairing;
mod pins;
mod serial;
mod streams;
mod tokens;
mod ws;

pub use browser::{Browser, BrowserOptions, DiscoveredServer};
pub use clock::{Clock, Sleep, SystemClock};
pub use failure::{Error, Failure, FailureKind, Result};
pub use hub::InvokeError;
pub use info::{pick_version, read_info, require_version};
pub use link::{HandlerError, Link, LinkState, LinkStatus, Subscription};
pub use options::ClientOptions;
pub use pairing::{MAX_WAIT, PairingClient, PairingError};
pub use pins::{Credentials, InvalidFingerprint, Pins};
pub use reqwest::{Method, RequestBuilder, Response, Url};
pub use serial::{SerialChange, SerialConnection, SerialEvent};
pub use streams::{
    Frame, OpenResult, StreamClose, StreamCloseReason, StreamConnection, StreamRefusal,
    StreamRefusalReason,
};

/// Skakel's own types the client's API is made of, so an app needs only this crate.
pub use skakel_protocol::{SkakelApp, SkakelHello, SkakelInfo};
pub use skakel_serial::{ErrorCode, FlowControl, LineSettings, ModemStatus, Parity, StopBits};
