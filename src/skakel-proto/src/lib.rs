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

/// Package `skakel.v2`: protocol version 2.
pub mod v2 {
    include!(concat!(env!("OUT_DIR"), "/skakel.v2.rs"));
}

pub use prost;
