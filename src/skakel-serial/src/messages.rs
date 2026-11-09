//! The control messages, one JSON object per text frame.

use serde::{Deserialize, Serialize};

use crate::settings::{ErrorCode, LineSettings, ModemStatus};

/// A control message from the client to the server, told apart by `op`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum ClientMessage {
    /// `lineSettings`: change the port's settings. Every field is required.
    LineSettings(LineSettings),
    /// `modemLines`: set the output lines. A line left out stays as it is. `rts` is ignored while
    /// flow control is RTS/CTS.
    ModemLines {
        /// Data terminal ready.
        #[serde(default)]
        dtr: Option<bool>,
        /// Request to send.
        #[serde(default)]
        rts: Option<bool>,
    },
    /// `break`: start or end a break.
    Break {
        /// True to start it, false to end it.
        on: bool,
    },
    /// `purge`: throw away what is buffered on the server.
    Purge {
        /// The bytes read from the port and not sent yet.
        #[serde(default)]
        input: bool,
        /// The bytes waiting to be written to the port.
        #[serde(default)]
        output: bool,
    },
}

/// A control message from the server to the client, told apart by `op`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum ServerMessage {
    /// `opened`: the first message after the upgrade, with the port as it is now.
    Opened {
        /// The port's settings.
        line_settings: LineSettings,
        /// The port's input lines.
        modem_status: ModemStatus,
    },
    /// `lineSettings`: the settings now on the port, after a change was applied. A client treats a
    /// change as done only when this comes back.
    LineSettings(LineSettings),
    /// `modemStatus`: an input line changed.
    ModemStatus(ModemStatus),
    /// `error`: a change the port refused, which leaves the settings as they were, or errors the
    /// port reported.
    Error {
        /// What kind of error.
        code: ErrorCode,
        /// What happened, for a person.
        #[serde(default)]
        detail: Option<String>,
    },
}

impl ClientMessage {
    /// The JSON text of the message, for a text frame.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("a control message is always valid JSON")
    }

    /// Reads a message from the client. `None` for anything that is not one: broken JSON, an
    /// unknown `op`, a missing field, a value that is not one of the lists, data bits outside 5 to
    /// 8 or a baud rate that is not positive.
    pub fn parse(json: &str) -> Option<Self> {
        match serde_json::from_str(json).ok()? {
            Self::LineSettings(LineSettings { baud, .. }) if baud < 1 => None,
            Self::LineSettings(LineSettings { data_bits, .. }) if !(5..=8).contains(&data_bits) => {
                None
            }
            message => Some(message),
        }
    }
}

impl ServerMessage {
    /// The JSON text of the message, for a text frame.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("a control message is always valid JSON")
    }

    /// Reads a message from the server. `None` for anything that is not one.
    pub fn parse(json: &str) -> Option<Self> {
        serde_json::from_str(json).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{FlowControl, Parity, StopBits};

    fn settings(
        baud: i32,
        data_bits: i32,
        parity: Parity,
        stop_bits: StopBits,
        flow_control: FlowControl,
    ) -> LineSettings {
        LineSettings {
            baud,
            data_bits,
            parity,
            stop_bits,
            flow_control,
        }
    }

    #[test]
    fn to_json_writes_the_op_and_the_wire_names() {
        let message = ClientMessage::LineSettings(settings(
            115200,
            8,
            Parity::None,
            StopBits::OnePointFive,
            FlowControl::RtsCts,
        ));

        assert_eq!(
            message.to_json(),
            r#"{"op":"lineSettings","baud":115200,"dataBits":8,"parity":"none","stopBits":"1.5","flowControl":"rtsCts"}"#
        );
    }

    #[test]
    fn to_json_nests_the_settings_and_status_in_opened() {
        let opened = ServerMessage::Opened {
            line_settings: settings(9600, 7, Parity::Even, StopBits::Two, FlowControl::XonXoff),
            modem_status: ModemStatus {
                cts: true,
                dsr: false,
                dcd: true,
                ri: false,
            },
        };

        let json = opened.to_json();

        assert_eq!(
            json,
            r#"{"op":"opened","lineSettings":{"baud":9600,"dataBits":7,"parity":"even","stopBits":"2","flowControl":"xonXoff"},"modemStatus":{"cts":true,"dsr":false,"dcd":true,"ri":false}}"#
        );
        assert_eq!(ServerMessage::parse(&json), Some(opened));
    }

    #[test]
    fn to_json_writes_the_other_messages_as_pinned() {
        assert_eq!(
            ClientMessage::ModemLines {
                dtr: None,
                rts: Some(false)
            }
            .to_json(),
            r#"{"op":"modemLines","dtr":null,"rts":false}"#
        );
        assert_eq!(
            ClientMessage::Break { on: true }.to_json(),
            r#"{"op":"break","on":true}"#
        );
        assert_eq!(
            ClientMessage::Purge {
                input: true,
                output: false
            }
            .to_json(),
            r#"{"op":"purge","input":true,"output":false}"#
        );
        assert_eq!(
            ServerMessage::ModemStatus(ModemStatus {
                cts: false,
                dsr: true,
                dcd: false,
                ri: true
            })
            .to_json(),
            r#"{"op":"modemStatus","cts":false,"dsr":true,"dcd":false,"ri":true}"#
        );
        assert_eq!(
            ServerMessage::Error {
                code: ErrorCode::Unsupported,
                detail: Some("1.5 stop bits with 8 data bits".into())
            }
            .to_json(),
            r#"{"op":"error","code":"unsupported","detail":"1.5 stop bits with 8 data bits"}"#
        );
        assert_eq!(
            ServerMessage::Error {
                code: ErrorCode::Overrun,
                detail: None
            }
            .to_json(),
            r#"{"op":"error","code":"overrun","detail":null}"#
        );
    }

    #[test]
    fn parse_reads_each_client_message() {
        let cases = [
            (
                r#"{"op":"lineSettings","baud":9600,"dataBits":8,"parity":"odd","stopBits":"1","flowControl":"none"}"#,
                ClientMessage::LineSettings(settings(
                    9600,
                    8,
                    Parity::Odd,
                    StopBits::One,
                    FlowControl::None,
                )),
            ),
            (
                r#"{"baud":9600,"dataBits":8,"parity":"odd","stopBits":"1","flowControl":"none","op":"lineSettings"}"#,
                ClientMessage::LineSettings(settings(
                    9600,
                    8,
                    Parity::Odd,
                    StopBits::One,
                    FlowControl::None,
                )),
            ),
            (
                r#"{"op":"modemLines","dtr":true}"#,
                ClientMessage::ModemLines {
                    dtr: Some(true),
                    rts: None,
                },
            ),
            (
                r#"{"op":"break","on":true}"#,
                ClientMessage::Break { on: true },
            ),
            (
                r#"{"op":"purge","input":true,"output":false}"#,
                ClientMessage::Purge {
                    input: true,
                    output: false,
                },
            ),
            (
                r#"{"op":"purge"}"#,
                ClientMessage::Purge {
                    input: false,
                    output: false,
                },
            ),
        ];

        for (json, expected) in cases {
            assert_eq!(ClientMessage::parse(json), Some(expected), "{json}");
        }
    }

    #[test]
    fn parse_leaves_a_modem_line_that_was_left_out_none() {
        assert_eq!(
            ClientMessage::parse(r#"{"op":"modemLines","rts":false}"#),
            Some(ClientMessage::ModemLines {
                dtr: None,
                rts: Some(false)
            })
        );
    }

    #[test]
    fn parse_refuses_anything_else_from_a_client() {
        let refused = [
            r#"{"op":"lineSettings","baud":9600,"dataBits":8,"parity":"odd","stopBits":"1"}"#,
            r#"{"op":"lineSettings","baud":9600,"dataBits":9,"parity":"odd","stopBits":"1","flowControl":"none"}"#,
            r#"{"op":"lineSettings","baud":0,"dataBits":8,"parity":"odd","stopBits":"1","flowControl":"none"}"#,
            r#"{"op":"lineSettings","baud":9600,"dataBits":8,"parity":"odd","stopBits":"3","flowControl":"none"}"#,
            r#"{"op":"lineSettings","baud":9600,"dataBits":8,"parity":1,"stopBits":"1","flowControl":"none"}"#,
            r#"{"op":"break"}"#,
            r#"{"op":"opened"}"#,
            r#"{"op":"reboot"}"#,
            r#"{"on":true}"#,
            "not json",
        ];

        for json in refused {
            assert_eq!(ClientMessage::parse(json), None, "{json}");
        }
    }

    #[test]
    fn parse_reads_an_error_and_applied_settings_from_the_server() {
        let applied = ServerMessage::LineSettings(settings(
            300,
            5,
            Parity::Mark,
            StopBits::One,
            FlowControl::None,
        ));

        assert_eq!(
            ServerMessage::parse(
                r#"{"op":"error","code":"unsupported","detail":"1.5 stop bits with 8 data bits"}"#
            ),
            Some(ServerMessage::Error {
                code: ErrorCode::Unsupported,
                detail: Some("1.5 stop bits with 8 data bits".into())
            })
        );
        assert_eq!(ServerMessage::parse(&applied.to_json()), Some(applied));
    }

    #[test]
    fn parse_refuses_what_a_server_would_not_send() {
        for json in [
            r#"{"op":"break","on":true}"#,
            r#"{"op":"error","code":"melted"}"#,
            "[]",
            "",
        ] {
            assert_eq!(ServerMessage::parse(json), None, "{json}");
        }
    }
}
