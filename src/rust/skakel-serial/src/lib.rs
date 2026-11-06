//! The serial stream's wire format: the stream type, line settings, modem lines, errors and the
//! control messages in both directions. See `docs/protocol.md` ("The serial stream type") at the
//! repository root; this is the Rust side of `Skakel.Serial`.
//!
//! Wire format only. The code that opens a real port stays in the app.
//!
//! Binary frames carry the port's bytes; text frames carry one control message each, told apart by
//! `op`. [`ClientMessage`] goes from the client to the server and [`ServerMessage`] the other way.
//! Both are strict about what they read: an unknown `op`, a missing required field or a value outside
//! the lists below is not a message, and `parse` gives `None`.

mod messages;
mod settings;

pub use messages::{ClientMessage, ServerMessage};
pub use settings::{ErrorCode, FlowControl, LineSettings, ModemStatus, Parity, StopBits};

/// The `serial` stream type: one serial port on the server, used by one client at a time.
pub const STREAM_TYPE: &str = "serial";

/// The query string parameter that names the port, by its id in the app's list of ports.
pub const PORT_QUERY: &str = "port";

/// Close code: the port reported a fault and was closed.
pub const CLOSE_PORT_FAULT: u16 = 4100;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stream_type_is_a_valid_one_with_the_port_query() {
        assert_eq!(STREAM_TYPE, "serial");
        assert_eq!(PORT_QUERY, "port");
        assert_eq!(CLOSE_PORT_FAULT, 4100);
    }
}
