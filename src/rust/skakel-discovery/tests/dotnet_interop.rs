//! A Rust probe finds a .NET answer and a .NET probe finds a Rust answer, over loopback, with the
//! .NET side being `src/Skakel/tests/Skakel.Discovery.Interop`.
//!
//! The tests need the `dotnet` SDK. Without it they say so and pass, so a machine that builds only
//! the Rust side is not stopped; the repository has no CI that would hide a missing SDK.

use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;

use skakel_discovery::net::{probe, serve_one};
use skakel_discovery::{DiscoveryAnswer, create_answer};
use skakel_protocol::SkakelApp;

fn project() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../Skakel/tests/Skakel.Discovery.Interop/Skakel.Discovery.Interop.csproj")
}

/// Builds the helper once for all tests, or returns false when there is no `dotnet`.
fn helper_ready() -> bool {
    static READY: OnceLock<bool> = OnceLock::new();
    *READY.get_or_init(|| {
        let built = Command::new("dotnet")
            .args(["build", "-nologo", "-v", "q"])
            .arg(project())
            .output();
        match built {
            Ok(output) if output.status.success() => true,
            Ok(output) => panic!(
                "dotnet build of the interop helper failed:
{}",
                String::from_utf8_lossy(&output.stdout)
            ),
            Err(_) => {
                eprintln!("dotnet is not installed: skipping the .NET interop test");
                false
            }
        }
    })
}

fn helper(args: &[&str]) -> Command {
    let mut command = Command::new("dotnet");
    command
        .args(["run", "--no-build", "--project"])
        .arg(project())
        .arg("--")
        .args(args);
    command
}

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn rust_probe_finds_a_dotnet_answer() {
    if !helper_ready() {
        return;
    }
    let mut server = KillOnDrop(
        helper(&["serve"])
            .stdout(Stdio::piped())
            .spawn()
            .expect("dotnet starts"),
    );
    let mut lines = BufReader::new(server.0.stdout.take().unwrap()).lines();
    let line = lines.next().expect("the helper prints its port").unwrap();
    let port: u16 = line.strip_prefix("PORT ").unwrap().parse().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();

    let found = probe(
        &client,
        SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_secs(5),
    )
    .unwrap();

    assert_eq!(found.len(), 1, "one .NET answer");
    assert_eq!(found[0].from.port(), port);
    assert_eq!(
        found[0].answer,
        DiscoveryAnswer {
            name: "dotnet-helper".into(),
            port: 5240,
            fingerprint: vec!["EF"; 32].join(":"),
            app: SkakelApp {
                id: "koppel".into(),
                version: "0.1.1".into()
            },
            versions: vec![1],
        }
    );
}

#[test]
fn dotnet_probe_finds_a_rust_answer() {
    if !helper_ready() {
        return;
    }
    let answer = DiscoveryAnswer {
        name: "rust-lab \u{E9}".into(),
        port: 6240,
        fingerprint: "ab".repeat(32),
        app: SkakelApp {
            id: "tweeling".into(),
            version: "0.2.0".into(),
        },
        versions: vec![1],
    };
    let bytes = create_answer(&answer).unwrap();
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let port = server.local_addr().unwrap().port();
    let answering = thread::spawn(move || while !serve_one(&server, &bytes).unwrap() {});

    let output = helper(&["probe", &port.to_string()])
        .output()
        .expect("dotnet starts");

    answering.join().unwrap();
    assert!(
        output.status.success(),
        "the .NET probe found nothing: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let found: DiscoveryAnswer = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(found.name, "rust-lab \u{E9}");
    assert_eq!(found.port, 6240);
    assert_eq!(found.fingerprint, vec!["AB"; 32].join(":"));
    assert_eq!(found.app, answer.app);
    assert_eq!(found.versions, [1]);
}
