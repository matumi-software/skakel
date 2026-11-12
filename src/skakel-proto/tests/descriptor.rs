//! Every message, field, enum value and call of the .proto files, written out and compared with
//! the checked-in `descriptor.golden`. A field number, a type or an enum number is the wire format,
//! so a change shows up here as a difference to review: it is a protocol change.
//!
//! To accept an intended change, regenerate the golden from `src/` and review the diff:
//!
//! ```sh
//! SKAKEL_UPDATE_GOLDEN=1 cargo test -p skakel-proto --test descriptor
//! ```

use std::fmt::Write;
use std::path::{Path, PathBuf};

use protox::Compiler;
use protox::prost_reflect::{Cardinality, DescriptorPool, Kind};

include!("../proto_files.rs");

fn golden_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/descriptor.golden")
}

fn kind_name(kind: &Kind) -> String {
    match kind {
        Kind::Message(message) => message.full_name().to_owned(),
        Kind::Enum(e) => e.full_name().to_owned(),
        other => format!("{other:?}").to_lowercase(),
    }
}

fn describe() -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../proto");
    let mut files = Vec::new();
    proto_files(&root, &root, &mut files);
    files.sort();
    let mut compiler = Compiler::new([&root]).expect("set up the compiler");
    compiler
        .open_files(&files)
        .unwrap_or_else(|error| panic!("the .proto files do not compile: {error:?}"));
    let pool: DescriptorPool = compiler.descriptor_pool();

    let mut out = String::new();
    for file in pool.files().filter(|f| f.name().starts_with("skakel/")) {
        writeln!(out, "file {}", file.name()).unwrap();
        writeln!(out, "package {}", file.package_name()).unwrap();
        let mut messages: Vec<_> = file.messages().collect();
        messages.sort_by_key(|m| m.full_name().to_owned());
        for message in messages {
            writeln!(out, "message {}", message.full_name()).unwrap();
            let mut fields: Vec<_> = message.fields().collect();
            fields.sort_by_key(|f| f.number());
            for field in fields {
                let label = match field.cardinality() {
                    Cardinality::Optional => "optional",
                    Cardinality::Required => "required",
                    Cardinality::Repeated => "repeated",
                };
                let oneof = field
                    .containing_oneof()
                    .filter(|o| !o.is_synthetic())
                    .map(|o| format!(" oneof {}", o.name()))
                    .unwrap_or_default();
                writeln!(
                    out,
                    "  {} = {} {} {}{}",
                    field.name(),
                    field.number(),
                    label,
                    kind_name(&field.kind()),
                    oneof
                )
                .unwrap();
            }
        }
        let mut enums: Vec<_> = file.enums().collect();
        enums.sort_by_key(|e| e.full_name().to_owned());
        for e in enums {
            writeln!(out, "enum {}", e.full_name()).unwrap();
            for value in e.values() {
                writeln!(out, "  {} = {}", value.name(), value.number()).unwrap();
            }
        }
        for service in file.services() {
            writeln!(out, "service {}", service.full_name()).unwrap();
            for method in service.methods() {
                writeln!(
                    out,
                    "  rpc {}({}{}) returns ({}{})",
                    method.name(),
                    if method.is_client_streaming() {
                        "stream "
                    } else {
                        ""
                    },
                    method.input().full_name(),
                    if method.is_server_streaming() {
                        "stream "
                    } else {
                        ""
                    },
                    method.output().full_name()
                )
                .unwrap();
            }
        }
        out.push('\n');
    }
    out
}

#[test]
fn the_descriptor_is_the_checked_in_golden() {
    let now = describe();
    let path = golden_path();
    if std::env::var_os("SKAKEL_UPDATE_GOLDEN").is_some() {
        std::fs::write(&path, &now).expect("write the golden");
        return;
    }
    let golden = std::fs::read_to_string(&path)
        .expect("tests/descriptor.golden is checked in; see this file's header to make it");
    // Line endings differ by checkout, the content must not.
    let golden = golden.replace("\r\n", "\n");
    assert_eq!(
        now, golden,
        "the .proto files no longer match tests/descriptor.golden. A change to a number or type \
         is a protocol change: update docs/protocol.md, then regenerate the golden (see the header)"
    );
}

#[test]
fn the_golden_names_every_number_the_wire_pins_cannot_reach() {
    // The byte pins cover a few messages; the golden must hold the rest, at least these.
    let now = describe();
    for line in [
        "  fingerprint = 1 optional string",
        "  next_fingerprint = 2 optional string",
        "  server = 1 optional string",
        "  client_id = 2 optional string",
        "  baud = 1 optional uint32",
        "  data_bits = 2 optional uint32",
        "  PARITY_ODD = 2",
        "  STOP_BITS_TWO = 3",
        "  FLOW_CONTROL_XON_XOFF = 3",
        "  SERIAL_ERROR_CODE_OVERRUN = 4",
    ] {
        assert!(now.contains(line), "missing {line}");
    }
}
