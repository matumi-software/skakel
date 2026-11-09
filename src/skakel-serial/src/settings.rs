//! A port's line settings and input lines, and the numbers `serial.proto` gives them.

use skakel_proto::v2 as wire;

/// Parity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

/// Stop bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StopBits {
    /// One stop bit.
    One,
    /// One and a half stop bits.
    OnePointFive,
    /// Two stop bits.
    Two,
}

/// Flow control, which the server runs on the real port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowControl {
    /// None.
    None,
    /// RTS/CTS. The server drives RTS itself.
    RtsCts,
    /// XON/XOFF. The port's driver handles them and they do not appear in the data.
    XonXoff,
}

/// Why the port refused a change or reported an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

/// A port's line settings: a `LineSettings` message on the wire, on its own or inside `opened`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LineSettings {
    /// Bits per second, 1 or more.
    pub baud: u32,
    /// 5 to 8.
    pub data_bits: u32,
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

impl Parity {
    pub(crate) fn to_wire(self) -> wire::Parity {
        match self {
            Self::None => wire::Parity::None,
            Self::Odd => wire::Parity::Odd,
            Self::Even => wire::Parity::Even,
            Self::Mark => wire::Parity::Mark,
            Self::Space => wire::Parity::Space,
        }
    }

    pub(crate) fn from_wire(value: i32) -> Option<Self> {
        Some(match wire::Parity::try_from(value).ok()? {
            wire::Parity::Unspecified => return None,
            wire::Parity::None => Self::None,
            wire::Parity::Odd => Self::Odd,
            wire::Parity::Even => Self::Even,
            wire::Parity::Mark => Self::Mark,
            wire::Parity::Space => Self::Space,
        })
    }
}

impl StopBits {
    pub(crate) fn to_wire(self) -> wire::StopBits {
        match self {
            Self::One => wire::StopBits::One,
            Self::OnePointFive => wire::StopBits::OnePointFive,
            Self::Two => wire::StopBits::Two,
        }
    }

    pub(crate) fn from_wire(value: i32) -> Option<Self> {
        Some(match wire::StopBits::try_from(value).ok()? {
            wire::StopBits::Unspecified => return None,
            wire::StopBits::One => Self::One,
            wire::StopBits::OnePointFive => Self::OnePointFive,
            wire::StopBits::Two => Self::Two,
        })
    }
}

impl FlowControl {
    pub(crate) fn to_wire(self) -> wire::FlowControl {
        match self {
            Self::None => wire::FlowControl::None,
            Self::RtsCts => wire::FlowControl::RtsCts,
            Self::XonXoff => wire::FlowControl::XonXoff,
        }
    }

    pub(crate) fn from_wire(value: i32) -> Option<Self> {
        Some(match wire::FlowControl::try_from(value).ok()? {
            wire::FlowControl::Unspecified => return None,
            wire::FlowControl::None => Self::None,
            wire::FlowControl::RtsCts => Self::RtsCts,
            wire::FlowControl::XonXoff => Self::XonXoff,
        })
    }
}

impl ErrorCode {
    pub(crate) fn to_wire(self) -> wire::SerialErrorCode {
        match self {
            Self::Unsupported => wire::SerialErrorCode::Unsupported,
            Self::Framing => wire::SerialErrorCode::Framing,
            Self::Parity => wire::SerialErrorCode::Parity,
            Self::Overrun => wire::SerialErrorCode::Overrun,
        }
    }

    pub(crate) fn from_wire(value: i32) -> Option<Self> {
        Some(match wire::SerialErrorCode::try_from(value).ok()? {
            wire::SerialErrorCode::Unspecified => return None,
            wire::SerialErrorCode::Unsupported => Self::Unsupported,
            wire::SerialErrorCode::Framing => Self::Framing,
            wire::SerialErrorCode::Parity => Self::Parity,
            wire::SerialErrorCode::Overrun => Self::Overrun,
        })
    }
}

impl LineSettings {
    pub(crate) fn to_wire(self) -> wire::LineSettings {
        wire::LineSettings {
            baud: self.baud,
            data_bits: self.data_bits,
            parity: self.parity.to_wire() as i32,
            stop_bits: self.stop_bits.to_wire() as i32,
            flow_control: self.flow_control.to_wire() as i32,
        }
    }

    /// The settings, or `None` when a field is zero, unspecified, a value this end does not know,
    /// or out of range: a baud rate below 1 or data bits outside 5 to 8.
    pub(crate) fn from_wire(settings: &wire::LineSettings) -> Option<Self> {
        if settings.baud < 1 || !(5..=8).contains(&settings.data_bits) {
            return None;
        }
        Some(Self {
            baud: settings.baud,
            data_bits: settings.data_bits,
            parity: Parity::from_wire(settings.parity)?,
            stop_bits: StopBits::from_wire(settings.stop_bits)?,
            flow_control: FlowControl::from_wire(settings.flow_control)?,
        })
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
