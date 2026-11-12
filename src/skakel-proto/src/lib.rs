//! The Rust code generated from Skakel's `.proto` files in `src/proto`, the wire format of protocol
//! version 2's control channel, streams and serial stream type. `docs/protocol.md` at the
//! repository root says what the messages mean.
//!
//! The code is generated at build time by `build.rs`, with protox compiling the `.proto` files in
//! Rust (no `protoc` needed), prost writing the messages and tonic writing the services. Every part
//! of Skakel that speaks version 2 takes its messages from here, so there is one copy of the code.
//!
//! - The messages are always there: [`v2::ConnectRequest`], [`v2::OpenRequest`],
//!   [`v2::SerialClientMessage`] and the rest. `bytes` fields are [`prost::bytes::Bytes`].
//! - The feature `client` adds a tonic client per service, such as
//!   `v2::control_service_client::ControlServiceClient`.
//! - The feature `server` adds a tonic server per service, such as
//!   `v2::control_service_server::ControlServiceServer` and its trait.
//!
//! Neither feature brings a transport: the client is generic over any service that sends HTTP/2
//! requests, and the server is a service an HTTP/2 server runs. Skakel's client and server bring
//! their own, pinned to the server's certificate.

#![forbid(unsafe_code)]

/// Package `skakel.v2`: protocol version 2. The generated items carry the comments of the
/// `.proto` files where there are any; the rest is as the file says.
#[allow(missing_docs)]
pub mod v2 {
    include!(concat!(env!("OUT_DIR"), "/skakel.v2.rs"));
}

pub use prost;

use skakel_wire::{Reason, SkakelHello};

/// The reasons the control channel can say a call is closing for are three of [`Reason`]; any other
/// reason is not one the server closes calls for, so it counts as stopping.
impl From<Reason> for v2::ClosingReason {
    fn from(reason: Reason) -> Self {
        match reason {
            Reason::Revoked => Self::Revoked,
            Reason::Rotated => Self::Rotated,
            _ => Self::Stopping,
        }
    }
}

/// What a client does with a closing reason: revoked and rotated are those reasons, and anything
/// else, an unspecified value included, counts as stopping.
impl From<v2::ClosingReason> for Reason {
    fn from(reason: v2::ClosingReason) -> Self {
        match reason {
            v2::ClosingReason::Revoked => Self::Revoked,
            v2::ClosingReason::Rotated => Self::Rotated,
            _ => Self::Stopping,
        }
    }
}

/// The reason a `Closing` message's `reason` number stands for. A number this end does not know
/// counts as stopping, as the protocol says.
pub fn closing_reason(number: i32) -> Reason {
    v2::ClosingReason::try_from(number)
        .map(Reason::from)
        .unwrap_or(Reason::Stopping)
}

impl From<v2::HelloResponse> for SkakelHello {
    fn from(hello: v2::HelloResponse) -> Self {
        SkakelHello {
            server: hello.server,
            client_id: hello.client_id,
        }
    }
}

impl From<SkakelHello> for v2::HelloResponse {
    fn from(hello: SkakelHello) -> Self {
        v2::HelloResponse {
            server: hello.server,
            client_id: hello.client_id,
        }
    }
}
