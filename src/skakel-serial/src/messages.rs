//! The control messages: one `SerialClientMessage` or `SerialServerMessage` per control frame,
//! encoded as `serial.proto` says.

use prost::Message;
use skakel_proto::v2 as wire;
use skakel_proto::v2::{serial_client_message, serial_server_message};

use crate::settings::{ErrorCode, LineSettings, ModemStatus};

/// A control message from the client to the server.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientMessage {
    /// `line_settings`: change the port's settings. Every field is required.
    LineSettings(LineSettings),
    /// `modem_lines`: set the output lines. A line left out stays as it is. `rts` is ignored while
    /// flow control is RTS/CTS.
    ModemLines {
        /// Data terminal ready.
        dtr: Option<bool>,
        /// Request to send.
        rts: Option<bool>,
    },
    /// `break_signal`: start or end a break.
    Break {
        /// True to start it, false to end it.
        on: bool,
    },
    /// `purge`: throw away what is buffered on the server.
    Purge {
        /// The bytes read from the port and not sent yet.
        input: bool,
        /// The bytes waiting to be written to the port.
        output: bool,
    },
}

/// A control message from the server to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServerMessage {
    /// `opened`: the first control message after `opened`, with the port as it is now.
    Opened {
        /// The port's settings.
        line_settings: LineSettings,
        /// The port's input lines.
        modem_status: ModemStatus,
    },
    /// `line_settings`: the settings now on the port, after a change was applied. A client treats a
    /// change as done only when this comes back.
    LineSettings(LineSettings),
    /// `modem_status`: an input line changed.
    ModemStatus(ModemStatus),
    /// `error`: a change the port refused, which leaves the settings as they were, or errors the
    /// port reported.
    Error {
        /// What kind of error.
        code: ErrorCode,
        /// What happened, for a person. Empty on the wire is `None`.
        detail: Option<String>,
    },
}

/// Why a control message from the client could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientMessageError {
    /// Not a `SerialClientMessage`.
    Malformed,
    /// A message of a kind this end does not know, which it ignores.
    UnknownKind,
    /// A `line_settings` change that [`LineSettings::is_valid`] refuses: a baud rate of 0, or a
    /// field that is unspecified, a value this end does not know or out of range. The server
    /// answers it with an `unsupported` error.
    UnsupportedSettings,
}

impl std::fmt::Display for ClientMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "not a serial control message",
            Self::UnknownKind => "a serial control message of a kind this end does not know",
            Self::UnsupportedSettings => "line settings with a value the port cannot take",
        })
    }
}

impl std::error::Error for ClientMessageError {}

/// Why a control message from the server could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServerMessageError {
    /// Not a `SerialServerMessage`.
    Malformed,
    /// A message of a kind this end does not know, which it ignores.
    UnknownKind,
    /// A message that lacks a part it needs: an `opened` without its line settings.
    Incomplete,
}

impl std::fmt::Display for ServerMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "not a serial control message",
            Self::UnknownKind => "a serial control message of a kind this end does not know",
            Self::Incomplete => "a serial control message without a part it needs",
        })
    }
}

impl std::error::Error for ServerMessageError {}

impl ClientMessage {
    /// The message, encoded, for a control frame.
    pub fn encode(&self) -> Vec<u8> {
        let message = match *self {
            Self::LineSettings(settings) => {
                serial_client_message::Message::LineSettings(settings.to_wire())
            }
            Self::ModemLines { dtr, rts } => {
                serial_client_message::Message::ModemLines(wire::ModemLines { dtr, rts })
            }
            Self::Break { on } => {
                serial_client_message::Message::BreakSignal(wire::BreakSignal { on })
            }
            Self::Purge { input, output } => {
                serial_client_message::Message::Purge(wire::Purge { input, output })
            }
        };
        wire::SerialClientMessage {
            message: Some(message),
        }
        .encode_to_vec()
    }

    /// Reads a message from the client.
    pub fn decode(bytes: &[u8]) -> Result<Self, ClientMessageError> {
        let message = wire::SerialClientMessage::decode(bytes)
            .map_err(|_| ClientMessageError::Malformed)?
            .message
            .ok_or(ClientMessageError::UnknownKind)?;
        Ok(match message {
            serial_client_message::Message::LineSettings(settings) => {
                let settings = LineSettings::from_wire(&settings);
                if !settings.is_valid() {
                    return Err(ClientMessageError::UnsupportedSettings);
                }
                Self::LineSettings(settings)
            }
            serial_client_message::Message::ModemLines(lines) => Self::ModemLines {
                dtr: lines.dtr,
                rts: lines.rts,
            },
            serial_client_message::Message::BreakSignal(signal) => Self::Break { on: signal.on },
            serial_client_message::Message::Purge(purge) => Self::Purge {
                input: purge.input,
                output: purge.output,
            },
        })
    }
}

impl ServerMessage {
    /// The message, encoded, for a control frame.
    pub fn encode(&self) -> Vec<u8> {
        let message = match self {
            Self::Opened {
                line_settings,
                modem_status,
            } => serial_server_message::Message::Opened(wire::SerialOpened {
                line_settings: Some(line_settings.to_wire()),
                modem_status: Some(modem_status.to_wire()),
            }),
            Self::LineSettings(settings) => {
                serial_server_message::Message::LineSettings(settings.to_wire())
            }
            Self::ModemStatus(status) => {
                serial_server_message::Message::ModemStatus(status.to_wire())
            }
            Self::Error { code, detail } => {
                serial_server_message::Message::Error(wire::SerialError {
                    code: code.to_wire(),
                    detail: detail.clone().unwrap_or_default(),
                })
            }
        };
        wire::SerialServerMessage {
            message: Some(message),
        }
        .encode_to_vec()
    }

    /// Reads a message from the server. A value this end does not know (a new error code, a new
    /// parity) is kept as `Unknown`, so a newer server's message is still read; only bytes that do
    /// not decode, a kind it does not know, or an `opened` without its settings are refused.
    pub fn decode(bytes: &[u8]) -> Result<Self, ServerMessageError> {
        let message = wire::SerialServerMessage::decode(bytes)
            .map_err(|_| ServerMessageError::Malformed)?
            .message
            .ok_or(ServerMessageError::UnknownKind)?;
        Ok(match message {
            serial_server_message::Message::Opened(opened) => Self::Opened {
                line_settings: LineSettings::from_wire(
                    opened
                        .line_settings
                        .as_ref()
                        .ok_or(ServerMessageError::Incomplete)?,
                ),
                modem_status: opened
                    .modem_status
                    .as_ref()
                    .map(ModemStatus::from_wire)
                    .unwrap_or_default(),
            },
            serial_server_message::Message::LineSettings(settings) => {
                Self::LineSettings(LineSettings::from_wire(&settings))
            }
            serial_server_message::Message::ModemStatus(status) => {
                Self::ModemStatus(ModemStatus::from_wire(&status))
            }
            serial_server_message::Message::Error(error) => Self::Error {
                code: ErrorCode::from_wire(error.code),
                detail: Some(error.detail).filter(|d| !d.is_empty()),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{DataBits, FlowControl, Parity, StopBits};

    fn settings(
        baud: u32,
        data_bits: u32,
        parity: Parity,
        stop_bits: StopBits,
        flow_control: FlowControl,
    ) -> LineSettings {
        LineSettings {
            baud,
            data_bits: DataBits::from_wire(data_bits),
            parity,
            stop_bits,
            flow_control,
        }
    }

    #[test]
    fn line_settings_are_written_with_the_proto_numbers() {
        let message = ClientMessage::LineSettings(settings(
            115_200,
            8,
            Parity::None,
            StopBits::OnePointFive,
            FlowControl::RtsCts,
        ));

        // line_settings (1) { baud (1) 115200, data_bits (2) 8, parity (3) NONE = 1,
        // stop_bits (4) ONE_POINT_FIVE = 2, flow_control (5) RTS_CTS = 2 }
        assert_eq!(
            message.encode(),
            [
                0x0A, 0x0C, 0x08, 0x80, 0x84, 0x07, 0x10, 0x08, 0x18, 0x01, 0x20, 0x02, 0x28, 0x02
            ]
        );
    }

    #[test]
    fn the_other_client_messages_are_written_as_pinned() {
        assert_eq!(
            ClientMessage::ModemLines {
                dtr: None,
                rts: Some(false)
            }
            .encode(),
            [0x12, 0x02, 0x10, 0x00]
        );
        assert_eq!(
            ClientMessage::Break { on: true }.encode(),
            [0x1A, 0x02, 0x08, 0x01]
        );
        assert_eq!(
            ClientMessage::Purge {
                input: true,
                output: false
            }
            .encode(),
            [0x22, 0x02, 0x08, 0x01]
        );
    }

    #[test]
    fn each_client_message_reads_back_as_written() {
        let cases = [
            ClientMessage::LineSettings(settings(
                9600,
                8,
                Parity::Odd,
                StopBits::One,
                FlowControl::None,
            )),
            ClientMessage::ModemLines {
                dtr: Some(true),
                rts: None,
            },
            ClientMessage::ModemLines {
                dtr: None,
                rts: None,
            },
            ClientMessage::Break { on: false },
            ClientMessage::Purge {
                input: false,
                output: true,
            },
        ];

        for message in cases {
            assert_eq!(
                ClientMessage::decode(&message.encode()),
                Ok(message.clone()),
                "{message:?}"
            );
        }
    }

    #[test]
    fn a_change_with_a_zero_or_unspecified_field_is_one_the_server_answers_unsupported() {
        let full = settings(9600, 8, Parity::Odd, StopBits::One, FlowControl::None).to_wire();
        let broken = [
            wire::LineSettings { baud: 0, ..full },
            wire::LineSettings {
                data_bits: 9,
                ..full
            },
            wire::LineSettings {
                data_bits: 0,
                ..full
            },
            wire::LineSettings { parity: 0, ..full },
            wire::LineSettings {
                stop_bits: 0,
                ..full
            },
            wire::LineSettings {
                flow_control: 7,
                ..full
            },
        ];

        for settings in broken {
            let bytes = wire::SerialClientMessage {
                message: Some(serial_client_message::Message::LineSettings(settings)),
            }
            .encode_to_vec();
            assert_eq!(
                ClientMessage::decode(&bytes),
                Err(ClientMessageError::UnsupportedSettings),
                "{settings:?}"
            );
        }
    }

    #[test]
    fn a_client_message_of_an_unknown_kind_or_not_a_message_is_told_apart() {
        assert_eq!(
            ClientMessage::decode(&[0x2A, 0x00]),
            Err(ClientMessageError::UnknownKind)
        );
        assert_eq!(
            ClientMessage::decode(&[0xFF]),
            Err(ClientMessageError::Malformed)
        );
    }

    #[test]
    fn opened_nests_the_settings_and_status_and_reads_back() {
        let opened = ServerMessage::Opened {
            line_settings: settings(9600, 7, Parity::Even, StopBits::Two, FlowControl::XonXoff),
            modem_status: ModemStatus {
                cts: true,
                dsr: false,
                dcd: true,
                ri: false,
            },
        };

        let bytes = opened.encode();

        assert_eq!(&bytes[..2], [0x0A, 0x13]);
        assert_eq!(ServerMessage::decode(&bytes), Ok(opened));
    }

    #[test]
    fn errors_and_status_read_back_and_an_empty_detail_is_none() {
        let cases = [
            ServerMessage::Error {
                code: ErrorCode::Unsupported,
                detail: Some("1.5 stop bits with 8 data bits".into()),
            },
            ServerMessage::Error {
                code: ErrorCode::Overrun,
                detail: None,
            },
            ServerMessage::ModemStatus(ModemStatus {
                cts: false,
                dsr: true,
                dcd: false,
                ri: true,
            }),
            ServerMessage::LineSettings(settings(
                300,
                5,
                Parity::Mark,
                StopBits::One,
                FlowControl::None,
            )),
        ];

        for message in cases {
            assert_eq!(
                ServerMessage::decode(&message.encode()),
                Ok(message.clone())
            );
        }
    }

    #[test]
    fn decode_refuses_only_what_is_not_a_message_or_lacks_its_settings() {
        let opened_without_settings = wire::SerialServerMessage {
            message: Some(serial_server_message::Message::Opened(
                wire::SerialOpened::default(),
            )),
        }
        .encode_to_vec();

        assert_eq!(
            ServerMessage::decode(&opened_without_settings),
            Err(ServerMessageError::Incomplete)
        );
        assert_eq!(
            ServerMessage::decode(&[0x2A, 0x00]),
            Err(ServerMessageError::UnknownKind)
        );
        assert_eq!(
            ServerMessage::decode(&[0xFF]),
            Err(ServerMessageError::Malformed)
        );
    }

    #[test]
    fn an_error_code_this_end_does_not_know_is_kept() {
        let bytes = wire::SerialServerMessage {
            message: Some(serial_server_message::Message::Error(wire::SerialError {
                code: 9,
                detail: "a code from a newer server".into(),
            })),
        }
        .encode_to_vec();

        let message = ServerMessage::decode(&bytes).unwrap();

        assert_eq!(
            message,
            ServerMessage::Error {
                code: ErrorCode::Unknown(9),
                detail: Some("a code from a newer server".into()),
            }
        );
        // And it goes back out as it came in.
        assert_eq!(message.encode(), bytes);
    }

    #[test]
    fn settings_with_values_this_end_does_not_know_are_kept_and_say_they_are_not_valid() {
        let wire_settings = wire::LineSettings {
            baud: 9600,
            data_bits: 9,
            parity: 6,
            stop_bits: 0,
            flow_control: 4,
        };
        let bytes = wire::SerialServerMessage {
            message: Some(serial_server_message::Message::Opened(wire::SerialOpened {
                line_settings: Some(wire_settings),
                modem_status: None,
            })),
        }
        .encode_to_vec();

        let Ok(ServerMessage::Opened { line_settings, .. }) = ServerMessage::decode(&bytes) else {
            panic!("an opened with unknown values is still read");
        };

        assert_eq!(line_settings.data_bits, DataBits::Unknown(9));
        assert_eq!(line_settings.parity, Parity::Unknown(6));
        assert_eq!(line_settings.stop_bits, StopBits::Unknown(0));
        assert_eq!(line_settings.flow_control, FlowControl::Unknown(4));
        assert!(!line_settings.is_valid());
        assert_eq!(line_settings.to_wire(), wire_settings);
    }

    #[test]
    fn data_bits_are_five_to_eight_and_nothing_else_is_valid() {
        for bits in 5..=8 {
            assert_eq!(DataBits::from_wire(bits).to_wire(), bits);
            assert!(!matches!(DataBits::from_wire(bits), DataBits::Unknown(_)));
        }
        for bits in [0, 4, 9, u32::MAX] {
            assert_eq!(DataBits::from_wire(bits), DataBits::Unknown(bits));
        }
        assert!(settings(1, 8, Parity::None, StopBits::One, FlowControl::None).is_valid());
        assert!(!settings(0, 8, Parity::None, StopBits::One, FlowControl::None).is_valid());
    }
}
