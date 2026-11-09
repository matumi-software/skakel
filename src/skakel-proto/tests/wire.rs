//! The generated messages write the bytes the .proto files say, and read what a newer end sends.
//! The bytes here are the wire format, so a change to one is a protocol change.

use prost::Message;
use prost::bytes::Bytes;
use skakel_proto::v2::{
    Certificates, Closing, ClosingReason, ConnectRequest, ConnectResponse, NextCertificateReceived,
    OpenRequest, OpenResponse, SerialClientMessage, SerialTarget, StreamOpen, StreamOpened,
    connect_request, connect_response, open_request, open_response, serial_client_message,
};

#[test]
fn certificates_are_written_as_the_proto_numbers_them() {
    let message = ConnectResponse {
        message: Some(connect_response::Message::Certificates(Certificates {
            fingerprint: "AB".into(),
            next_fingerprint: "CD".into(),
        })),
    };

    assert_eq!(
        message.encode_to_vec(),
        [0x0A, 0x08, 0x0A, 0x02, b'A', b'B', 0x12, 0x02, b'C', b'D']
    );
}

#[test]
fn an_empty_next_fingerprint_is_left_out() {
    let message = ConnectResponse {
        message: Some(connect_response::Message::Certificates(Certificates {
            fingerprint: "AB".into(),
            next_fingerprint: String::new(),
        })),
    };

    assert_eq!(
        message.encode_to_vec(),
        [0x0A, 0x04, 0x0A, 0x02, b'A', b'B']
    );
}

#[test]
fn closing_carries_its_reason_as_a_number() {
    let message = ConnectResponse {
        message: Some(connect_response::Message::Closing(Closing {
            reason: ClosingReason::Rotated as i32,
        })),
    };

    assert_eq!(message.encode_to_vec(), [0x12, 0x02, 0x08, 0x02]);
}

#[test]
fn next_certificate_received_is_the_clients_first_kind() {
    let message = ConnectRequest {
        message: Some(connect_request::Message::NextCertificateReceived(
            NextCertificateReceived {
                fingerprint: "CD".into(),
            },
        )),
    };

    assert_eq!(
        message.encode_to_vec(),
        [0x0A, 0x04, 0x0A, 0x02, b'C', b'D']
    );
}

#[test]
fn a_message_of_a_kind_this_end_does_not_know_reads_as_none() {
    // Field 3 of ConnectResponse, a kind a later version might add, holding an empty message.
    let message = ConnectResponse::decode(&[0x1A, 0x00][..]).unwrap();

    assert_eq!(message.message, None);
}

#[test]
fn a_closing_reason_this_end_does_not_know_keeps_its_number() {
    let message = ConnectResponse::decode(&[0x12, 0x02, 0x08, 0x09][..]).unwrap();

    let Some(connect_response::Message::Closing(closing)) = message.message else {
        panic!("not a closing");
    };
    assert_eq!(closing.reason, 9);
    assert!(ClosingReason::try_from(closing.reason).is_err());
}

#[test]
fn open_names_the_type_and_carries_the_target_as_bytes() {
    let target = SerialTarget {
        port: "COM3".into(),
    }
    .encode_to_vec();
    let message = OpenRequest {
        frame: Some(open_request::Frame::Open(StreamOpen {
            stream_type: "serial".into(),
            target: Bytes::from(target.clone()),
        })),
    };

    assert_eq!(target, [0x0A, 0x04, b'C', b'O', b'M', b'3']);
    let mut expected = vec![0x0A, 0x10, 0x0A, 0x06];
    expected.extend_from_slice(b"serial");
    expected.extend_from_slice(&[0x12, 0x06]);
    expected.extend_from_slice(&target);
    assert_eq!(message.encode_to_vec(), expected);
}

#[test]
fn opened_is_an_empty_first_field() {
    let message = OpenResponse {
        frame: Some(open_response::Frame::Opened(StreamOpened {})),
    };

    assert_eq!(message.encode_to_vec(), [0x0A, 0x00]);
}

#[test]
fn data_and_control_frames_are_fields_two_and_three() {
    let data = OpenRequest {
        frame: Some(open_request::Frame::Data(Bytes::from_static(b"hi"))),
    };
    let control = OpenResponse {
        frame: Some(open_response::Frame::Control(Bytes::from_static(b"ok"))),
    };

    assert_eq!(data.encode_to_vec(), [0x12, 0x02, b'h', b'i']);
    assert_eq!(control.encode_to_vec(), [0x1A, 0x02, b'o', b'k']);
}

#[test]
fn a_data_frame_costs_at_most_five_bytes_on_top_of_its_data() {
    // With gRPC's 5-byte prefix that is the 10 bytes docs/protocol.md promises, up to the 16 MiB a
    // stream frame may be.
    for length in [0, 1, 127, 128, 16_383, 16_384, 1 << 20, 16 << 20] {
        let frame = OpenResponse {
            frame: Some(open_response::Frame::Data(Bytes::from(vec![0u8; length]))),
        };

        assert!(frame.encoded_len() - length <= 5, "{length}");
    }
}

#[test]
fn data_is_read_as_bytes_that_share_the_buffer() {
    let wire = Bytes::from_static(&[0x12, 0x03, 1, 2, 3]);

    let frame = OpenRequest::decode(wire.clone()).unwrap();

    let Some(open_request::Frame::Data(data)) = frame.frame else {
        panic!("not data");
    };
    assert_eq!(&data[..], [1, 2, 3]);
    // Read out of the same allocation, not copied.
    assert_eq!(data.as_ptr(), wire[2..].as_ptr());
}

#[test]
fn serial_control_messages_are_numbered_as_the_proto_says() {
    let message = SerialClientMessage {
        message: Some(serial_client_message::Message::BreakSignal(
            skakel_proto::v2::BreakSignal { on: true },
        )),
    };

    assert_eq!(message.encode_to_vec(), [0x1A, 0x02, 0x08, 0x01]);
}
