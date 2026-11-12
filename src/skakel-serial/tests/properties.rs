//! Properties of the serial control messages: a message written is read back, a value this end
//! does not know is kept, and bytes from a stranger are a message or an error.

use proptest::prelude::*;
use skakel_serial::{
    ClientMessage, DataBits, ErrorCode, FlowControl, LineSettings, ModemStatus, Parity,
    ServerMessage, StopBits, port_of, target,
};

fn parities() -> impl Strategy<Value = Parity> {
    prop_oneof![
        Just(Parity::None),
        Just(Parity::Odd),
        Just(Parity::Even),
        Just(Parity::Mark),
        Just(Parity::Space),
        any::<i32>().prop_map(Parity::Unknown),
    ]
}

fn stop_bits() -> impl Strategy<Value = StopBits> {
    prop_oneof![
        Just(StopBits::One),
        Just(StopBits::OnePointFive),
        Just(StopBits::Two),
        any::<i32>().prop_map(StopBits::Unknown),
    ]
}

fn flow_controls() -> impl Strategy<Value = FlowControl> {
    prop_oneof![
        Just(FlowControl::None),
        Just(FlowControl::RtsCts),
        Just(FlowControl::XonXoff),
        any::<i32>().prop_map(FlowControl::Unknown),
    ]
}

fn data_bits() -> impl Strategy<Value = DataBits> {
    prop_oneof![
        Just(DataBits::Five),
        Just(DataBits::Six),
        Just(DataBits::Seven),
        Just(DataBits::Eight),
        any::<u32>().prop_map(DataBits::Unknown),
    ]
}

fn error_codes() -> impl Strategy<Value = ErrorCode> {
    prop_oneof![
        Just(ErrorCode::Unsupported),
        Just(ErrorCode::Framing),
        Just(ErrorCode::Parity),
        Just(ErrorCode::Overrun),
        any::<i32>().prop_map(ErrorCode::Unknown),
    ]
}

fn settings() -> impl Strategy<Value = LineSettings> {
    (
        any::<u32>(),
        data_bits(),
        parities(),
        stop_bits(),
        flow_controls(),
    )
        .prop_map(
            |(baud, data_bits, parity, stop_bits, flow_control)| LineSettings {
                baud,
                data_bits,
                parity,
                stop_bits,
                flow_control,
            },
        )
}

fn modem_status() -> impl Strategy<Value = ModemStatus> {
    (any::<bool>(), any::<bool>(), any::<bool>(), any::<bool>())
        .prop_map(|(cts, dsr, dcd, ri)| ModemStatus { cts, dsr, dcd, ri })
}

fn server_messages() -> impl Strategy<Value = ServerMessage> {
    prop_oneof![
        (settings(), modem_status()).prop_map(|(line_settings, modem_status)| {
            ServerMessage::Opened {
                line_settings,
                modem_status,
            }
        }),
        settings().prop_map(ServerMessage::LineSettings),
        modem_status().prop_map(ServerMessage::ModemStatus),
        (error_codes(), proptest::option::of(".{1,40}"))
            .prop_map(|(code, detail)| ServerMessage::Error { code, detail }),
    ]
}

fn client_messages() -> impl Strategy<Value = ClientMessage> {
    prop_oneof![
        settings().prop_map(ClientMessage::LineSettings),
        (
            proptest::option::of(any::<bool>()),
            proptest::option::of(any::<bool>())
        )
            .prop_map(|(dtr, rts)| ClientMessage::ModemLines { dtr, rts }),
        any::<bool>().prop_map(|on| ClientMessage::Break { on }),
        (any::<bool>(), any::<bool>())
            .prop_map(|(input, output)| ClientMessage::Purge { input, output }),
    ]
}

proptest! {
    /// A server message, with any value in it, is read back, and written again as the same bytes.
    /// A value this end does not know is kept and not dropped.
    #[test]
    fn a_server_message_survives_its_own_encoding(message in server_messages()) {
        let bytes = message.encode();
        let read = ServerMessage::decode(&bytes).expect("a message this end wrote is readable");
        prop_assert_eq!(read.encode(), bytes);
    }

    /// A client message is read back, except line settings a port cannot take, which are refused
    /// as unsupported.
    #[test]
    fn a_client_message_survives_its_own_encoding(message in client_messages()) {
        let bytes = message.encode();
        match ClientMessage::decode(&bytes) {
            Ok(read) => prop_assert_eq!(read.encode(), bytes),
            Err(_) => {
                let ClientMessage::LineSettings(settings) = message else {
                    return Err(TestCaseError::fail("only line settings are refused"));
                };
                prop_assert!(!settings.is_valid());
            }
        }
    }

    /// Settings that are valid are never refused.
    #[test]
    fn valid_settings_are_never_refused(settings in settings()) {
        let read = ClientMessage::decode(&ClientMessage::LineSettings(settings).encode());
        prop_assert_eq!(read.is_ok(), settings.is_valid());
    }

    /// Any bytes are a message or an error, and a message read is written again without a panic.
    #[test]
    fn arbitrary_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..256)) {
        if let Ok(m) = ClientMessage::decode(&data) { let _ = m.encode(); }
        if let Ok(m) = ServerMessage::decode(&data) { let _ = m.encode(); }
        let _ = port_of(&data);
    }

    /// A target names its port and reads back.
    #[test]
    fn a_target_reads_back(port in ".{1,40}") {
        prop_assert_eq!(port_of(&target(&port)), Some(port));
    }
}
