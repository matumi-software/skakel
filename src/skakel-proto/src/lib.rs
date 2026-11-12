//! The Rust code generated from Skakel's `.proto` files in `src/proto`, the wire format of protocol
//! version 3's control channel and streams, and the serial stream type
//! (package `skakel.streams.serial.v1`, which versions on its own). `docs/protocol.md` at the
//! repository root says what the messages mean.
//!
//! The code is generated at build time by `build.rs`, with protox compiling the `.proto` files in
//! Rust (no `protoc` needed), prost writing the messages and tonic writing the services. Every part
//! of Skakel that speaks version 3 takes its messages from here, so there is one copy of the code.
//!
//! - The messages are always there: [`v3::ConnectRequest`], [`v3::OpenRequest`],
//!   [`serial::SerialClientMessage`] and the rest. `bytes` fields are [`prost::bytes::Bytes`].
//! - The feature `client` adds a tonic client per service, such as
//!   `v3::control_service_client::ControlServiceClient`.
//! - The feature `server` adds a tonic server per service, such as
//!   `v3::control_service_server::ControlServiceServer` and its trait.
//!
//! Neither feature brings a transport: the client is generic over any service that sends HTTP/2
//! requests, and the server is a service an HTTP/2 server runs. Skakel's client and server bring
//! their own, pinned to the server's certificate.

#![forbid(unsafe_code)]

/// Package `skakel.v3`: protocol version 3, the control and stream services. The generated items
/// carry the comments of the `.proto` files where there are any; the rest is as the file says.
#[allow(missing_docs)]
pub mod v3 {
    include!(concat!(env!("OUT_DIR"), "/skakel.v3.rs"));
}

/// Package `skakel.streams.serial.v1`: the serial stream type's messages. They are carried in the
/// `target` and `control` bytes of a stream, and version apart from the core protocol.
#[allow(missing_docs)]
pub mod serial {
    include!(concat!(env!("OUT_DIR"), "/skakel.streams.serial.v1.rs"));
}

pub use prost;

use skakel_wire::{Reason, SkakelHello};

/// The reasons the control channel can say a call is closing for are three of [`Reason`]; any other
/// reason is not one the server closes calls for, so it counts as stopping.
impl From<Reason> for v3::ClosingReason {
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
impl From<v3::ClosingReason> for Reason {
    fn from(reason: v3::ClosingReason) -> Self {
        match reason {
            v3::ClosingReason::Revoked => Self::Revoked,
            v3::ClosingReason::Rotated => Self::Rotated,
            _ => Self::Stopping,
        }
    }
}

/// The reason a `Closing` message's `reason` number stands for. A number this end does not know
/// counts as stopping, as the protocol says.
pub fn closing_reason(number: i32) -> Reason {
    v3::ClosingReason::try_from(number)
        .map(Reason::from)
        .unwrap_or(Reason::Stopping)
}

impl From<v3::HelloResponse> for SkakelHello {
    fn from(hello: v3::HelloResponse) -> Self {
        SkakelHello {
            server: hello.server,
            client_id: hello.client_id,
        }
    }
}

impl From<SkakelHello> for v3::HelloResponse {
    fn from(hello: SkakelHello) -> Self {
        v3::HelloResponse {
            server: hello.server,
            client_id: hello.client_id,
        }
    }
}
