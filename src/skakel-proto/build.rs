//! Generates the Rust code for the .proto files in `src/proto`, in Rust, with protox, so building
//! Skakel needs no `protoc`. The messages are always generated; the tonic clients and servers are
//! generated too, and compiled only with the `client` and `server` features.

use std::path::{Path, PathBuf};

/// Every .proto file under `dir`, relative to `root`, with forward slashes as protox wants.
fn proto_files(root: &Path, dir: &Path, found: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).expect("read the proto folder") {
        let path = entry.expect("read a proto folder entry").path();
        if path.is_dir() {
            proto_files(root, &path, found);
        } else if path.extension().is_some_and(|e| e == "proto") {
            let relative = path.strip_prefix(root).expect("a path under the root");
            found.push(relative.to_string_lossy().replace('\\', "/"));
        }
    }
}

fn main() {
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("set by cargo"))
        .join("..")
        .join("proto");
    println!("cargo:rerun-if-changed={}", root.display());

    let mut files = Vec::new();
    proto_files(&root, &root, &mut files);
    files.sort();
    for file in &files {
        println!("cargo:rerun-if-changed={}", root.join(file).display());
    }

    let descriptors = protox::compile(&files, [&root])
        .unwrap_or_else(|error| panic!("the .proto files do not compile: {error:?}"));

    tonic_prost_build::configure()
        // `bytes` fields as `Bytes`, so a stream's data is handed on without another copy.
        .bytes(".")
        // The generated `connect` helpers need tonic's own transport, which Skakel does not use:
        // its connections are pinned to a certificate fingerprint.
        .build_transport(false)
        .client_mod_attribute(".", "#[cfg(feature = \"client\")]")
        .server_mod_attribute(".", "#[cfg(feature = \"server\")]")
        .compile_fds(descriptors)
        .expect("generate the Rust code");
}
