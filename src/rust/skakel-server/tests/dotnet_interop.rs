//! The .NET client against this server, over loopback. Each test starts a server, runs one
//! scenario of `src/Skakel/tests/Skakel.Client.Interop` (the real `Skakel.Client`: its pinned
//! HTTP, its token client, its SignalR hub connection and its streams) against it, and does on the
//! server what the scenario asks for when it prints `WAIT <action>`: approve a pairing request,
//! prepare a certificate, revoke a client. The scenario's own checks are what it prints as `OK`;
//! a check that fails ends it with a non-zero exit code and the test fails with what it said.
//!
//! The tests need the `dotnet` SDK. Without it they say so and pass, so a machine that builds only
//! the Rust side is not stopped; the repository has no CI that would hide a missing SDK.

mod common;

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::Duration;

use common::*;
use skakel_server::SkakelServer;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

fn project() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../Skakel/tests/Skakel.Client.Interop/Skakel.Client.Interop.csproj")
}

/// Builds the driver once for all tests, or returns false when there is no `dotnet`.
fn driver_ready() -> bool {
    static READY: OnceLock<bool> = OnceLock::new();
    *READY.get_or_init(|| {
        let built = std::process::Command::new("dotnet")
            .args(["build", "-nologo", "-v", "q"])
            .arg(project())
            .output();
        match built {
            Ok(output) if output.status.success() => true,
            Ok(output) => panic!(
                "dotnet build of the interop driver failed:\n{}",
                String::from_utf8_lossy(&output.stdout)
            ),
            Err(_) => {
                eprintln!("dotnet is not installed: skipping the .NET client tests");
                false
            }
        }
    })
}

/// One run of a scenario: its output to read and its input to answer with.
struct Driver {
    child: Child,
    lines: Lines<BufReader<ChildStdout>>,
    stdin: ChildStdin,
    stderr: Option<tokio::task::JoinHandle<String>>,
    log: Vec<String>,
}

impl Driver {
    fn start(scenario: &str, server: &SkakelServer, extra: &[&str]) -> Self {
        let mut child = Command::new("dotnet")
            .args(["run", "--no-build", "--project"])
            .arg(project())
            .args(["--", scenario])
            .arg(server.local_addr().port().to_string())
            .arg(server.fingerprint())
            .args(extra)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("dotnet starts");
        let lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let stdin = child.stdin.take().unwrap();
        let mut stderr_pipe = child.stderr.take().unwrap();
        let stderr = tokio::spawn(async move {
            let mut text = String::new();
            let _ = stderr_pipe.read_to_string(&mut text).await;
            text
        });
        Self {
            child,
            lines,
            stdin,
            stderr: Some(stderr),
            log: vec![],
        }
    }

    /// Reads lines until one starts with `prefix`, and returns it. Fails with what the scenario
    /// said when it ends first.
    async fn until(&mut self, prefix: &str) -> String {
        loop {
            let next = tokio::time::timeout(Duration::from_secs(90), self.lines.next_line())
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "the scenario said nothing for 90 seconds waiting for '{prefix}'\n{}",
                        self.log.join("\n")
                    )
                })
                .expect("readable output");
            let Some(line) = next else {
                let status = self.child.wait().await.unwrap();
                let stderr = match self.stderr.take() {
                    Some(handle) => handle.await.unwrap(),
                    None => String::new(),
                };
                panic!(
                    "the scenario ended ({status}) before '{prefix}'\n--- said\n{}\n--- stderr\n{stderr}",
                    self.log.join("\n")
                );
            };
            self.log.push(line.clone());
            if line.starts_with(prefix) {
                return line;
            }
        }
    }

    async fn wait_for(&mut self, action: &str) {
        self.until(&format!("WAIT {action}")).await;
    }

    /// Tells the scenario the action is done.
    async fn done(&mut self) {
        self.stdin.write_all(b"DONE\n").await.unwrap();
        self.stdin.flush().await.unwrap();
    }

    /// Waits for the scenario to end and checks it passed. What it said is returned.
    async fn finish(mut self) -> Vec<String> {
        self.until("PASSED").await;
        let status = tokio::time::timeout(Duration::from_secs(30), self.child.wait())
            .await
            .expect("the scenario ends")
            .unwrap();
        assert!(
            status.success(),
            "the scenario failed ({status})\n{}",
            self.log.join("\n")
        );
        self.log
    }
}

fn credentials(server: &SkakelServer) -> impl std::future::Future<Output = (String, String)> {
    let clients = server.clients();
    async move {
        let client = clients.register("interop client").await.unwrap();
        (client.client_id, client.client_secret)
    }
}

async fn run_with_credentials(scenario: &str, server: &SkakelServer) -> Driver {
    let (id, secret) = credentials(server).await;
    Driver::start(scenario, server, &[&id, &secret])
}

async fn bench() -> Option<SkakelServer> {
    if !driver_ready() {
        return None;
    }
    Some(start().await)
}

/// The id of the request a client of this name has waiting, once the server shows it.
async fn waiting_request(server: &SkakelServer, name: &str) -> String {
    for _ in 0..250 {
        let overview = server.pairing().overview().await;
        if let Some(request) = overview
            .requests
            .iter()
            .find(|r| r.client_name == name && r.state == "waiting")
        {
            return request.id.clone();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the request of '{name}' never showed on the server");
}

fn code_of(line: &str) -> String {
    line.strip_prefix("CODE ").unwrap().trim().to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_dotnet_client_reads_info_and_refuses_another_certificate() {
    let Some(server) = bench().await else { return };

    let driver = Driver::start("info", &server, &[]);

    driver.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dotnet_probe_finds_the_rust_discovery_answer() {
    let Some(server) = bench().await else { return };
    let udp = server.discovery_addr().unwrap().port().to_string();

    let mut driver = Driver::start("discover", &server, &[&udp]);

    let line = driver.until("PORT ").await;
    assert_eq!(line, format!("PORT {}", server.local_addr().port()));
    driver.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_dotnet_client_pairs_with_the_rust_server_and_signs_in_with_what_it_gets() {
    let Some(server) = bench().await else { return };
    let mut driver = Driver::start("pair", &server, &[]);

    // Approved with the code the client worked out for itself.
    let code = code_of(&driver.until("CODE ").await);
    driver.wait_for("approve").await;
    let id = waiting_request(&server, "interop client").await;
    assert_eq!(
        server.pairing().approve(&id, &code).await.unwrap(),
        skakel_server::Approval::Approved
    );
    driver.done().await;
    let credentials = driver.until("CREDENTIALS ").await;
    let client_id = credentials.split(' ').nth(1).unwrap();
    assert_eq!(
        server.clients().name_of(client_id).as_deref(),
        Some("interop client")
    );

    // Refused on the server.
    driver.until("CODE ").await;
    driver.wait_for("deny").await;
    let id = waiting_request(&server, "refused client").await;
    assert!(server.pairing().deny(&id).await);
    driver.done().await;

    // The code typed wrong three times.
    driver.until("CODE ").await;
    driver.wait_for("wrong-codes").await;
    let id = waiting_request(&server, "wrong code client").await;
    for _ in 0..3 {
        server.pairing().approve(&id, "000000").await.unwrap();
    }
    driver.done().await;

    // Withdrawn by the client.
    driver.until("CODE ").await;
    driver.wait_for("seen").await;
    waiting_request(&server, "withdrawn client").await;
    driver.done().await;
    driver.wait_for("gone").await;
    let overview = server.pairing().overview().await;
    assert!(
        overview
            .requests
            .iter()
            .all(|r| r.client_name != "withdrawn client"),
        "the withdrawn request is off the list"
    );
    driver.done().await;

    driver.finish().await;
    assert_eq!(
        server.clients().all().len(),
        1,
        "only the approved request registered a client"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_dotnet_client_is_refused_wrong_secrets_and_then_held_off_by_the_failure_limit() {
    let Some(server) = bench().await else { return };

    let driver = run_with_credentials("credentials", &server).await;

    driver.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_dotnet_link_connects_the_hub_calls_it_and_hears_it() {
    let Some(server) = bench().await else { return };

    let driver = run_with_credentials("link", &server).await;

    driver.finish().await;
    assert_eq!(server.clients().all().len(), 1);
    assert!(
        server.clients().all()[0].last_seen.is_some(),
        "the token request marked the client as seen"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_dotnet_client_follows_a_certificate_handover_and_acknowledges_it() {
    let Some(server) = bench().await else { return };
    let mut driver = run_with_credentials("handover", &server).await;

    driver.wait_for("prepare").await;
    let next = server
        .keys()
        .prepare_next_certificate()
        .await
        .unwrap()
        .unwrap();
    driver.done().await;
    driver.wait_for("acknowledged").await;
    for _ in 0..500 {
        if server.clients().all()[0].has_next_certificate {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        server.clients().all()[0].has_next_certificate,
        "the server heard the client stored the next certificate"
    );
    driver.done().await;
    driver.wait_for("switch").await;
    let switched = server.keys().switch_certificate().await.unwrap().unwrap();
    assert!(switched.not_received.is_empty());
    assert!(skakel_protocol::fingerprints::are_equal(
        &presented_fingerprint(server.local_addr()).await,
        &next
    ));
    driver.done().await;

    driver.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_dotnet_client_forgets_a_handover_that_was_cancelled() {
    let Some(server) = bench().await else { return };
    let mut driver = run_with_credentials("handover-cancel", &server).await;

    driver.wait_for("prepare").await;
    server.keys().prepare_next_certificate().await.unwrap();
    driver.done().await;
    driver.wait_for("acknowledged").await;
    driver.done().await;
    driver.wait_for("cancel").await;
    assert!(server.keys().cancel_next_certificate().await.unwrap());
    driver.done().await;

    driver.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn revoking_a_client_ends_its_dotnet_link_and_streams_for_good() {
    let Some(server) = bench().await else { return };
    let (id, secret) = credentials(&server).await;
    let mut driver = Driver::start("revoked", &server, &[&id, &secret]);

    driver.wait_for("revoke").await;
    assert!(server.clients().revoke(&id).await.unwrap());
    driver.done().await;

    let said = driver.finish().await;
    assert!(said.iter().any(|l| l == "CLOSE 4001"), "{said:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn rotating_a_secret_ends_its_dotnet_link_and_streams_with_rotated() {
    let Some(server) = bench().await else { return };
    let (id, secret) = credentials(&server).await;
    let mut driver = Driver::start("rotated", &server, &[&id, &secret]);

    driver.wait_for("rotate").await;
    assert!(server.clients().rotate_secret(&id).await.unwrap().is_some());
    driver.done().await;

    let said = driver.finish().await;
    assert!(said.iter().any(|l| l == "CLOSE 4002"), "{said:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn stopping_the_server_tells_the_dotnet_link_and_streams() {
    let Some(server) = bench().await else { return };
    let (id, secret) = credentials(&server).await;
    let mut driver = Driver::start("stopping", &server, &[&id, &secret]);

    driver.wait_for("stop").await;
    server.shutdown().await;
    driver.done().await;

    let said = driver.finish().await;
    assert!(said.iter().any(|l| l == "CLOSE 4003"), "{said:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_dotnet_client_opens_streams_and_is_refused_them_with_words() {
    let Some(server) = bench().await else { return };

    let driver = run_with_credentials("streams", &server).await;

    driver.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_dotnet_serial_connection_runs_against_the_rust_stream() {
    let Some(server) = bench().await else { return };

    let driver = run_with_credentials("serial", &server).await;

    driver.finish().await;
}
