//! Generates the Rust code for the .proto files in `proto/` of this crate, in Rust, with protox, so building
//! Skakel needs no `protoc`. The messages are always generated; the tonic clients and servers are
//! generated too, and compiled only with the `client` and `server` features.

use std::path::{Path, PathBuf};

include!("proto_files.rs");

fn main() {
    // Inside the crate, so the package a release publishes carries the files it builds from.
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("set by cargo")).join("proto");
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
