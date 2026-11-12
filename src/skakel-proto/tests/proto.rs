//! The .proto files of protocol version 2 in `src/proto` compile, and the services, calls and
//! field numbers are the ones `docs/protocol.md` gives. Field numbers are the wire format, so a
//! change to one here is a protocol change.

use std::path::{Path, PathBuf};

use protox::Compiler;
use protox::prost_reflect::{DescriptorPool, Kind};

fn proto_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../proto")
}

include!("../proto_files.rs");

fn compile() -> DescriptorPool {
    let root = proto_root();
    let mut files = Vec::new();
    proto_files(&root, &root, &mut files);
    files.sort();
    assert_eq!(
        files,
        [
            "skakel/v2/control.proto",
            "skakel/v2/serial.proto",
            "skakel/v2/streams.proto"
        ]
    );

    let mut compiler = Compiler::new([&root]).expect("set up the compiler");
    compiler
        .open_files(&files)
        .unwrap_or_else(|error| panic!("the .proto files do not compile: {error:?}"));
    compiler.descriptor_pool()
}

/// Each field of a oneof as (name, number).
fn oneof_fields(pool: &DescriptorPool, message: &str, oneof: &str) -> Vec<(String, u32)> {
    let message = pool
        .get_message_by_name(message)
        .unwrap_or_else(|| panic!("no message {message}"));
    let oneof = message
        .oneofs()
        .find(|o| o.name() == oneof)
        .unwrap_or_else(|| panic!("no oneof {oneof}"));
    oneof
        .fields()
        .map(|field| (field.name().to_owned(), field.number()))
        .collect()
}

fn named(pairs: &[(&str, u32)]) -> Vec<(String, u32)> {
    pairs
        .iter()
        .map(|(name, number)| ((*name).to_owned(), *number))
        .collect()
}

#[test]
fn the_proto_files_compile_in_package_skakel_v2() {
    let pool = compile();

    for file in pool.files() {
        assert_eq!(file.package_name(), "skakel.v2", "{}", file.name());
    }
}

#[test]
fn the_control_service_has_connect_both_ways_and_hello_unary() {
    let pool = compile();
    let service = pool
        .get_service_by_name("skakel.v2.ControlService")
        .expect("the control service");

    let calls: Vec<_> = service
        .methods()
        .map(|m| {
            (
                m.name().to_owned(),
                m.is_client_streaming(),
                m.is_server_streaming(),
                m.input().full_name().to_owned(),
                m.output().full_name().to_owned(),
            )
        })
        .collect();

    assert_eq!(
        calls,
        [
            (
                "Connect".to_owned(),
                true,
                true,
                "skakel.v2.ConnectRequest".to_owned(),
                "skakel.v2.ConnectResponse".to_owned()
            ),
            (
                "Hello".to_owned(),
                false,
                false,
                "skakel.v2.HelloRequest".to_owned(),
                "skakel.v2.HelloResponse".to_owned()
            ),
        ]
    );
}

#[test]
fn the_stream_service_opens_a_stream_both_ways() {
    let pool = compile();
    let service = pool
        .get_service_by_name("skakel.v2.StreamService")
        .expect("the stream service");
    let open = service.methods().next().expect("one call");

    assert_eq!(service.methods().len(), 1);
    assert_eq!(open.name(), "Open");
    assert!(open.is_client_streaming() && open.is_server_streaming());
    assert_eq!(open.input().full_name(), "skakel.v2.OpenRequest");
    assert_eq!(open.output().full_name(), "skakel.v2.OpenResponse");
}

#[test]
fn control_messages_keep_their_field_numbers() {
    let pool = compile();

    assert_eq!(
        oneof_fields(&pool, "skakel.v2.ConnectRequest", "message"),
        named(&[("next_certificate_received", 1)])
    );
    assert_eq!(
        oneof_fields(&pool, "skakel.v2.ConnectResponse", "message"),
        named(&[("certificates", 1), ("closing", 2)])
    );
}

#[test]
fn stream_frames_keep_their_field_numbers_and_carry_bytes() {
    let pool = compile();

    assert_eq!(
        oneof_fields(&pool, "skakel.v2.OpenRequest", "frame"),
        named(&[("open", 1), ("data", 2), ("control", 3)])
    );
    assert_eq!(
        oneof_fields(&pool, "skakel.v2.OpenResponse", "frame"),
        named(&[("opened", 1), ("data", 2), ("control", 3)])
    );
    for message in ["skakel.v2.OpenRequest", "skakel.v2.OpenResponse"] {
        let message = pool.get_message_by_name(message).unwrap();
        for name in ["data", "control"] {
            let field = message.get_field_by_name(name).unwrap();
            assert!(matches!(field.kind(), Kind::Bytes), "{name} is bytes");
        }
    }
}

#[test]
fn serial_messages_keep_their_field_numbers() {
    let pool = compile();

    assert_eq!(
        oneof_fields(&pool, "skakel.v2.SerialClientMessage", "message"),
        named(&[
            ("line_settings", 1),
            ("modem_lines", 2),
            ("break_signal", 3),
            ("purge", 4)
        ])
    );
    assert_eq!(
        oneof_fields(&pool, "skakel.v2.SerialServerMessage", "message"),
        named(&[
            ("opened", 1),
            ("line_settings", 2),
            ("modem_status", 3),
            ("error", 4)
        ])
    );
    let target = pool.get_message_by_name("skakel.v2.SerialTarget").unwrap();
    assert_eq!(target.get_field_by_name("port").unwrap().number(), 1);
}

#[test]
fn closing_reasons_keep_their_numbers() {
    let pool = compile();
    let reasons = pool
        .get_enum_by_name("skakel.v2.ClosingReason")
        .expect("the closing reasons");

    let values: Vec<_> = reasons
        .values()
        .map(|v| (v.name().to_owned(), v.number()))
        .collect();

    assert_eq!(
        values,
        [
            ("CLOSING_REASON_UNSPECIFIED".to_owned(), 0),
            ("CLOSING_REASON_REVOKED".to_owned(), 1),
            ("CLOSING_REASON_ROTATED".to_owned(), 2),
            ("CLOSING_REASON_STOPPING".to_owned(), 3),
        ]
    );
}
