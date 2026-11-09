//! The serial stream's wire format: the stream type, its target, line settings, modem lines, errors
//! and the control messages in both directions. See `docs/protocol.md` ("The serial stream type") at
//! the repository root; the messages are `SerialClientMessage` and `SerialServerMessage` in
//! `src/proto/skakel/v2/serial.proto`.
//!
//! Wire format only. The code that opens a real port stays in the app.
//!
//! Data frames carry the port's bytes; control frames carry one control message each.
//! [`ClientMessage`] goes from the client to the server and [`ServerMessage`] the other way. Both
//! are strict about what they read: a value outside the lists below, or a kind this end does not
//! know, is not a message it uses.

mod messages;
mod settings;

use prost::Message;

pub use messages::{ClientMessage, ClientMessageError, ServerMessage};
pub use settings::{ErrorCode, FlowControl, LineSettings, ModemStatus, Parity, StopBits};

/// The `serial` stream type: one serial port on the server, used by one client at a time.
pub const STREAM_TYPE: &str = "serial";

/// The reason, in the domain `skakel.streams.serial`, a stream ends with when the port reported a
/// fault and was closed. The stream ends with `ABORTED`.
pub const PORT_FAULT: &str = "PORT_FAULT";

/// The target of a stream to the port with this id in the app's list of ports: a `SerialTarget`,
/// encoded, for the `open` frame.
pub fn target(port: &str) -> Vec<u8> {
    skakel_proto::v2::SerialTarget {
        port: port.to_owned(),
    }
    .encode_to_vec()
}

/// The port a stream's target names, or `None` when the target is not a `SerialTarget` or names no
/// port.
pub fn port_of(target: &[u8]) -> Option<String> {
    skakel_proto::v2::SerialTarget::decode(target)
        .ok()
        .map(|target| target.port)
        .filter(|port| !port.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stream_type_and_its_fault_reason_are_the_protocols() {
        assert_eq!(STREAM_TYPE, "serial");
        assert_eq!(PORT_FAULT, "PORT_FAULT");
    }

    #[test]
    fn a_target_names_its_port_and_reads_back() {
        assert_eq!(target("COM3"), [0x0A, 0x04, b'C', b'O', b'M', b'3']);
        assert_eq!(port_of(&target("COM3")).as_deref(), Some("COM3"));
        assert_eq!(port_of(&target("")), None);
        assert_eq!(port_of(&[0xFF]), None);
    }
}
