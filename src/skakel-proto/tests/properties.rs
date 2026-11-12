//! Properties of the generated messages: what is written reads back, and bytes from a stranger
//! decode to a message or to an error, never to a panic.

use proptest::prelude::*;
use prost::Message;
use prost::bytes::Bytes;
use skakel_proto::v2::{
    Certificates, Closing, ConnectRequest, ConnectResponse, HelloResponse, NextCertificateReceived,
    OpenRequest, OpenResponse, SerialClientMessage, SerialServerMessage, StreamOpen,
    connect_request, connect_response, open_request, open_response,
};

fn bytes() -> impl Strategy<Value = Bytes> {
    proptest::collection::vec(any::<u8>(), 0..64).prop_map(Bytes::from)
}

fn open_requests() -> impl Strategy<Value = OpenRequest> {
    prop_oneof![
        ("[a-z0-9-]{0,16}", bytes()).prop_map(|(stream_type, target)| OpenRequest {
            frame: Some(open_request::Frame::Open(StreamOpen {
                stream_type,
                target
            })),
        }),
        bytes().prop_map(|d| OpenRequest {
            frame: Some(open_request::Frame::Data(d))
        }),
        bytes().prop_map(|d| OpenRequest {
            frame: Some(open_request::Frame::Control(d))
        }),
        Just(OpenRequest { frame: None }),
    ]
}

fn open_responses() -> impl Strategy<Value = OpenResponse> {
    prop_oneof![
        bytes().prop_map(|d| OpenResponse {
            frame: Some(open_response::Frame::Data(d))
        }),
        bytes().prop_map(|d| OpenResponse {
            frame: Some(open_response::Frame::Control(d))
        }),
        Just(OpenResponse {
            frame: Some(open_response::Frame::Opened(Default::default()))
        }),
        Just(OpenResponse { frame: None }),
    ]
}

fn connect_responses() -> impl Strategy<Value = ConnectResponse> {
    prop_oneof![
        (".{0,95}", ".{0,95}").prop_map(|(fingerprint, next_fingerprint)| ConnectResponse {
            message: Some(connect_response::Message::Certificates(Certificates {
                fingerprint,
                next_fingerprint,
            })),
        }),
        any::<i32>().prop_map(|reason| ConnectResponse {
            message: Some(connect_response::Message::Closing(Closing { reason })),
        }),
        Just(ConnectResponse { message: None }),
    ]
}

proptest! {
    #[test]
    fn stream_frames_read_back_as_written(request in open_requests(), response in open_responses()) {
        prop_assert_eq!(OpenRequest::decode(request.encode_to_vec().as_slice()).unwrap(), request);
        prop_assert_eq!(OpenResponse::decode(response.encode_to_vec().as_slice()).unwrap(), response);
    }

    #[test]
    fn control_messages_read_back_as_written(
        response in connect_responses(),
        fingerprint in ".{0,95}",
        server in ".{0,40}",
        client_id in ".{0,40}",
    ) {
        prop_assert_eq!(ConnectResponse::decode(response.encode_to_vec().as_slice()).unwrap(), response);
        let request = ConnectRequest {
            message: Some(connect_request::Message::NextCertificateReceived(
                NextCertificateReceived { fingerprint },
            )),
        };
        prop_assert_eq!(ConnectRequest::decode(request.encode_to_vec().as_slice()).unwrap(), request);
        let hello = HelloResponse { server, client_id };
        prop_assert_eq!(HelloResponse::decode(hello.encode_to_vec().as_slice()).unwrap(), hello);
    }

    /// Any bytes decode to a message or an error. A decoded message is written again without a
    /// panic.
    #[test]
    fn arbitrary_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        if let Ok(m) = OpenRequest::decode(data.as_slice()) { let _ = m.encode_to_vec(); }
        if let Ok(m) = OpenResponse::decode(data.as_slice()) { let _ = m.encode_to_vec(); }
        if let Ok(m) = ConnectRequest::decode(data.as_slice()) { let _ = m.encode_to_vec(); }
        if let Ok(m) = ConnectResponse::decode(data.as_slice()) { let _ = m.encode_to_vec(); }
        if let Ok(m) = HelloResponse::decode(data.as_slice()) { let _ = m.encode_to_vec(); }
        if let Ok(m) = SerialClientMessage::decode(data.as_slice()) { let _ = m.encode_to_vec(); }
        if let Ok(m) = SerialServerMessage::decode(data.as_slice()) { let _ = m.encode_to_vec(); }
    }
}
