//! A port's line settings and input lines, and the words they are written with.

use serde::{Deserialize, Serialize};

/// Parity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Parity {
    /// No parity bit.
    None,
    /// Odd parity.
    Odd,
    /// Even parity.
    Even,
    /// The parity bit is always 1.
    Mark,
    /// The parity bit is always 0.
    Space,
}

/// Stop bits, written `"1"`, `"1.5"` or `"2"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StopBits {
    /// One stop bit.
    #[serde(rename = "1")]
    One,
    /// One and a half stop bits.
    #[serde(rename = "1.5")]
    OnePointFive,
    /// Two stop bits.
    #[serde(rename = "2")]
    Two,
}

/// Flow control, which the server runs on the real port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FlowControl {
    /// None.
    None,
    /// RTS/CTS. The server drives RTS itself.
    RtsCts,
    /// XON/XOFF. The port's driver handles them and they do not appear in the data.
    XonXoff,
}

/// Why the port refused a change or reported an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ErrorCode {
    /// The port cannot take that value.
    Unsupported,
    /// A framing error.
    Framing,
    /// A parity error.
    Parity,
    /// The port's receive buffer overran.
    Overrun,
}

/// A port's line settings. On the wire these are the fields of a `lineSettings` message, and the
/// `lineSettings` object inside `opened`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LineSettings {
    /// Bits per second.
    pub baud: i32,
    /// 5 to 8.
    pub data_bits: i32,
    /// The parity.
    pub parity: Parity,
    /// The stop bits.
    pub stop_bits: StopBits,
    /// The flow control.
    pub flow_control: FlowControl,
}

/// The state of a port's input lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModemStatus {
    /// Clear to send.
    pub cts: bool,
    /// Data set ready.
    pub dsr: bool,
    /// Data carrier detect.
    pub dcd: bool,
    /// Ring indicator.
    pub ri: bool,
}
