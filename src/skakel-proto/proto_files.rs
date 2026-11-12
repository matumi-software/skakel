// The one walker for the .proto files, included by build.rs and by tests/proto.rs.

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
