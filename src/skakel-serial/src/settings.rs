//! A port's line settings and input lines, and the numbers `serial.proto` gives them.
//!
//! A value this end does not know, or the unspecified 0, is kept as `Unknown` with the number the
//! peer sent, so a message from a newer peer is still a message. [`LineSettings::is_valid`] says
//! whether a port can be asked for the settings.

use skakel_proto::v2 as wire;

/// Parity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
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
    /// A value this end does not know, or the unspecified 0, as the peer sent it. A server answers
    /// a change that has one with `unsupported`.
    Unknown(i32),
}

/// Stop bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StopBits {
    /// One stop bit.
    One,
    /// One and a half stop bits.
    OnePointFive,
    /// Two stop bits.
    Two,
    /// A value this end does not know, or the unspecified 0, as the peer sent it.
    Unknown(i32),
}

/// Data bits per character.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DataBits {
    /// Five data bits.
    Five,
    /// Six data bits.
    Six,
    /// Seven data bits.
    Seven,
    /// Eight data bits.
    Eight,
    /// A count outside 5 to 8, as the peer sent it. A server answers a change that has one with
    /// `unsupported`.
    Unknown(u32),
}

/// Flow control, which the server runs on the real port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FlowControl {
    /// None.
    None,
    /// RTS/CTS. The server drives RTS itself.
    RtsCts,
    /// XON/XOFF. The port's driver handles them and they do not appear in the data.
    XonXoff,
    /// A value this end does not know, or the unspecified 0, as the peer sent it.
    Unknown(i32),
}

/// Why the port refused a change or reported an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// The port cannot take that value.
    Unsupported,
    /// A framing error.
    Framing,
    /// A parity error.
    Parity,
    /// The port's receive buffer overran.
    Overrun,
    /// A code this end does not know, or the unspecified 0, as the peer sent it. A newer server may
    /// add codes; the message is kept, not dropped.
    Unknown(i32),
}

/// A port's line settings: a `LineSettings` message on the wire, on its own or inside `opened`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LineSettings {
    /// Bits per second, 1 or more.
    pub baud: u32,
    /// The data bits.
    pub data_bits: DataBits,
    /// The parity.
    pub parity: Parity,
    /// The stop bits.
    pub stop_bits: StopBits,
    /// The flow control.
    pub flow_control: FlowControl,
}

/// The state of a port's input lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
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

impl DataBits {
    pub(crate) fn to_wire(self) -> u32 {
        match self {
            Self::Five => 5,
            Self::Six => 6,
            Self::Seven => 7,
            Self::Eight => 8,
            Self::Unknown(count) => count,
        }
    }

    pub(crate) fn from_wire(value: u32) -> Self {
        match value {
            5 => Self::Five,
            6 => Self::Six,
            7 => Self::Seven,
            8 => Self::Eight,
            other => Self::Unknown(other),
        }
    }
}

impl Parity {
    pub(crate) fn to_wire(self) -> i32 {
        match self {
            Self::None => wire::Parity::None as i32,
            Self::Odd => wire::Parity::Odd as i32,
            Self::Even => wire::Parity::Even as i32,
            Self::Mark => wire::Parity::Mark as i32,
            Self::Space => wire::Parity::Space as i32,
            Self::Unknown(value) => value,
        }
    }

    pub(crate) fn from_wire(value: i32) -> Self {
        match wire::Parity::try_from(value) {
            Ok(wire::Parity::None) => Self::None,
            Ok(wire::Parity::Odd) => Self::Odd,
            Ok(wire::Parity::Even) => Self::Even,
            Ok(wire::Parity::Mark) => Self::Mark,
            Ok(wire::Parity::Space) => Self::Space,
            Ok(wire::Parity::Unspecified) | Err(_) => Self::Unknown(value),
        }
    }
}

impl StopBits {
    pub(crate) fn to_wire(self) -> i32 {
        match self {
            Self::One => wire::StopBits::One as i32,
            Self::OnePointFive => wire::StopBits::OnePointFive as i32,
            Self::Two => wire::StopBits::Two as i32,
            Self::Unknown(value) => value,
        }
    }

    pub(crate) fn from_wire(value: i32) -> Self {
        match wire::StopBits::try_from(value) {
            Ok(wire::StopBits::One) => Self::One,
            Ok(wire::StopBits::OnePointFive) => Self::OnePointFive,
            Ok(wire::StopBits::Two) => Self::Two,
            Ok(wire::StopBits::Unspecified) | Err(_) => Self::Unknown(value),
        }
    }
}

impl FlowControl {
    pub(crate) fn to_wire(self) -> i32 {
        match self {
            Self::None => wire::FlowControl::None as i32,
            Self::RtsCts => wire::FlowControl::RtsCts as i32,
            Self::XonXoff => wire::FlowControl::XonXoff as i32,
            Self::Unknown(value) => value,
        }
    }

    pub(crate) fn from_wire(value: i32) -> Self {
        match wire::FlowControl::try_from(value) {
            Ok(wire::FlowControl::None) => Self::None,
            Ok(wire::FlowControl::RtsCts) => Self::RtsCts,
            Ok(wire::FlowControl::XonXoff) => Self::XonXoff,
            Ok(wire::FlowControl::Unspecified) | Err(_) => Self::Unknown(value),
        }
    }
}

impl ErrorCode {
    pub(crate) fn to_wire(self) -> i32 {
        match self {
            Self::Unsupported => wire::SerialErrorCode::Unsupported as i32,
            Self::Framing => wire::SerialErrorCode::Framing as i32,
            Self::Parity => wire::SerialErrorCode::Parity as i32,
            Self::Overrun => wire::SerialErrorCode::Overrun as i32,
            Self::Unknown(value) => value,
        }
    }

    pub(crate) fn from_wire(value: i32) -> Self {
        match wire::SerialErrorCode::try_from(value) {
            Ok(wire::SerialErrorCode::Unsupported) => Self::Unsupported,
            Ok(wire::SerialErrorCode::Framing) => Self::Framing,
            Ok(wire::SerialErrorCode::Parity) => Self::Parity,
            Ok(wire::SerialErrorCode::Overrun) => Self::Overrun,
            Ok(wire::SerialErrorCode::Unspecified) | Err(_) => Self::Unknown(value),
        }
    }
}

impl LineSettings {
    pub(crate) fn to_wire(self) -> wire::LineSettings {
        wire::LineSettings {
            baud: self.baud,
            data_bits: self.data_bits.to_wire(),
            parity: self.parity.to_wire(),
            stop_bits: self.stop_bits.to_wire(),
            flow_control: self.flow_control.to_wire(),
        }
    }

    /// The settings as the peer sent them. A value this end does not know is kept as `Unknown`.
    pub(crate) fn from_wire(settings: &wire::LineSettings) -> Self {
        Self {
            baud: settings.baud,
            data_bits: DataBits::from_wire(settings.data_bits),
            parity: Parity::from_wire(settings.parity),
            stop_bits: StopBits::from_wire(settings.stop_bits),
            flow_control: FlowControl::from_wire(settings.flow_control),
        }
    }

    /// Whether a port can be asked for these settings: a baud rate of 1 or more and every other
    /// field a value this end knows. A server answers a change that fails this with `unsupported`.
    pub fn is_valid(&self) -> bool {
        self.baud >= 1
            && !matches!(self.data_bits, DataBits::Unknown(_))
            && !matches!(self.parity, Parity::Unknown(_))
            && !matches!(self.stop_bits, StopBits::Unknown(_))
            && !matches!(self.flow_control, FlowControl::Unknown(_))
    }
}

impl ModemStatus {
    pub(crate) fn to_wire(self) -> wire::ModemStatus {
        wire::ModemStatus {
            cts: self.cts,
            dsr: self.dsr,
            dcd: self.dcd,
            ri: self.ri,
        }
    }

    pub(crate) fn from_wire(status: &wire::ModemStatus) -> Self {
        Self {
            cts: status.cts,
            dsr: status.dsr,
            dcd: status.dcd,
            ri: status.ri,
        }
    }
}
