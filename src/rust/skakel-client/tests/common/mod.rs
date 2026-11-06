//! What the integration tests share: a real `Skakel.Server` on Kestrel, started and driven through
//! `src/Skakel/tests/Skakel.Server.Interop`, the way the .NET client's tests use `SkakelHost`.
//!
//! The tests need the `dotnet` SDK. Without it they say so and pass, so a machine that builds only
//! the Rust side is not stopped; the repository has no CI that would hide a missing SDK. Everything
//! is on loopback.

#![allow(dead_code)]

use std::future::Future;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use serde_json::Value;
use skakel_client::{Clock, Credentials, Pins, Sleep, Url};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::{Notify, oneshot};

fn project() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../Skakel/tests/Skakel.Server.Interop/Skakel.Server.Interop.csproj")
}

/// Builds the server once for all tests, or returns false when there is no `dotnet`.
fn built() -> bool {
    static BUILT: OnceLock<bool> = OnceLock::new();
    *BUILT.get_or_init(|| {
        let built = std::process::Command::new("dotnet")
            // No build server and no shared compiler: they would keep the pipes this reads open.
            .args([
                "build",
                "-nologo",
                "-v",
                "q",
                "-nodeReuse:false",
                "-p:UseSharedCompilation=false",
            ])
            .arg(project())
            .output();
        match built {
            Ok(output) if output.status.success() => true,
            Ok(output) => panic!(
                "dotnet build of the interop server failed:\n{}",
                String::from_utf8_lossy(&output.stdout)
            ),
            Err(_) => {
                eprintln!("dotnet is not installed: skipping the tests that need a .NET server");
                false
            }
        }
    })
}

/// A running interop program. Dropping it lets go of its stdin, which stops it and every server it
/// started.
pub struct Dotnet {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: tokio::io::Lines<BufReader<ChildStdout>>,
}

/// A server the interop program started.
#[derive(Debug, Clone)]
pub struct Server {
    pub id: u64,
    pub port: u16,
    pub fingerprint: String,
}

impl Server {
    pub fn address(&self) -> Url {
        Url::parse(&format!("https://127.0.0.1:{}/", self.port)).unwrap()
    }

    pub fn pins(&self) -> Pins {
        Pins::new(&self.fingerprint).unwrap()
    }
}

impl Dotnet {
    /// Starts the interop program, or `None` when there is no `dotnet`.
    pub async fn start() -> Option<Self> {
        if !built() {
            return None;
        }
        let mut child = Command::new("dotnet")
            .args(["run", "--no-build", "--project"])
            .arg(project())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("dotnet starts");
        let stdin = child.stdin.take();
        let lines = BufReader::new(child.stdout.take().unwrap()).lines();
        Some(Self {
            child,
            stdin,
            lines,
        })
    }

    /// One command and its answer's JSON. Panics on `ERR`.
    pub async fn command(&mut self, line: &str) -> Value {
        let stdin = self.stdin.as_mut().expect("the program is running");
        stdin
            .write_all(format!("{line}\n").as_bytes())
            .await
            .unwrap();
        stdin.flush().await.unwrap();
        let answer = tokio::time::timeout(Duration::from_secs(60), self.lines.next_line())
            .await
            .unwrap_or_else(|_| panic!("no answer to {line}"))
            .unwrap()
            .unwrap_or_else(|| panic!("the program ended before it answered {line}"));
        match answer.split_once(' ') {
            Some(("OK", json)) => serde_json::from_str(json).unwrap(),
            _ => panic!("{line}: {answer}"),
        }
    }

    /// A server with a new state.
    pub async fn server(&mut self) -> Server {
        self.server_in("state-0", None, None).await
    }

    /// A server that answers discovery on the UDP port.
    pub async fn server_with_discovery(&mut self, udp: u16) -> Server {
        self.server_in("state-0", None, Some(udp)).await
    }

    /// A server in the state `store`: another one started in the same state has the same
    /// certificate and clients, as one server restarted.
    pub async fn server_in(&mut self, store: &str, tcp: Option<u16>, udp: Option<u16>) -> Server {
        let mut line = format!("start {store}");
        if tcp.is_some() || udp.is_some() {
            line.push_str(&format!(" {}", tcp.unwrap_or(0)));
        }
        if let Some(udp) = udp {
            line.push_str(&format!(" {udp}"));
        }
        let started = self.command(&line).await;
        Server {
            id: started["id"].as_u64().unwrap(),
            port: started["port"].as_u64().unwrap() as u16,
            fingerprint: started["fingerprint"].as_str().unwrap().to_owned(),
        }
    }

    pub async fn stop(&mut self, server: &Server) {
        self.command(&format!("stop {}", server.id)).await;
    }

    pub async fn register(&mut self, server: &Server) -> Credentials {
        let client = self
            .command(&format!("register {} bench-1", server.id))
            .await;
        Credentials::new(
            client["clientId"].as_str().unwrap(),
            client["clientSecret"].as_str().unwrap(),
        )
    }

    /// The pairing requests waiting on the server, as (id, client name).
    pub async fn requests(&mut self, server: &Server) -> Vec<(String, String)> {
        self.command(&format!("requests {}", server.id))
            .await
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r["id"].as_str().unwrap().to_owned(),
                    r["clientName"].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    }

    /// Types the code on the server, as a person would. The approval's name.
    pub async fn approve(&mut self, server: &Server, request: &str, code: &str) -> String {
        self.command(&format!("approve {} {request} {code}", server.id))
            .await
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// The server's clients, as (id, name, has a next certificate).
    pub async fn clients(&mut self, server: &Server) -> Vec<(String, String, bool)> {
        self.command(&format!("clients {}", server.id))
            .await
            .as_array()
            .unwrap()
            .iter()
            .map(|c| {
                (
                    c["id"].as_str().unwrap().to_owned(),
                    c["name"].as_str().unwrap().to_owned(),
                    c["hasNextCertificate"].as_bool().unwrap(),
                )
            })
            .collect()
    }
}

impl Drop for Dotnet {
    fn drop(&mut self) {
        // Closing stdin ends the program, and the servers with it.
        self.stdin.take();
        let _ = self.child.start_kill();
    }
}

/// A free UDP port on loopback, for a server to answer discovery on.
pub fn free_udp() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A free TCP port on loopback.
pub fn free_tcp() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Skips the rest of a test, saying why, when there is no `dotnet`.
#[macro_export]
macro_rules! dotnet {
    () => {
        match $crate::common::Dotnet::start().await {
            Some(dotnet) => dotnet,
            None => return,
        }
    };
}

/// What an event raised, for a test to wait on.
pub struct Recorder<T> {
    seen: Arc<Mutex<Vec<T>>>,
    arrived: Arc<Notify>,
}

impl<T> Clone for Recorder<T> {
    fn clone(&self) -> Self {
        Self {
            seen: self.seen.clone(),
            arrived: self.arrived.clone(),
        }
    }
}

impl<T: Clone + Send + 'static> Recorder<T> {
    pub fn new() -> Self {
        Self {
            seen: Arc::new(Mutex::new(Vec::new())),
            arrived: Arc::new(Notify::new()),
        }
    }

    pub fn record(&self, value: T) {
        self.seen.lock().unwrap().push(value);
        self.arrived.notify_waiters();
    }

    pub fn seen(&self) -> Vec<T> {
        self.seen.lock().unwrap().clone()
    }

    /// The first value, among those seen so far and after, that satisfies `matches`.
    pub async fn wait(&self, matches: impl Fn(&T) -> bool) -> T {
        self.wait_for(Duration::from_secs(20), matches).await
    }

    /// Waits until at least `count` of the values seen satisfy `matches`.
    pub async fn wait_count(&self, count: usize, matches: impl Fn(&T) -> bool) {
        let timeout = Duration::from_secs(20);
        tokio::time::timeout(timeout, async {
            loop {
                let arrived = self.arrived.notified();
                tokio::pin!(arrived);
                arrived.as_mut().enable();
                if self.seen().iter().filter(|v| matches(v)).count() >= count {
                    return;
                }
                arrived.await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("fewer than {count} values matched in {timeout:?}"));
    }

    pub async fn wait_for(&self, timeout: Duration, matches: impl Fn(&T) -> bool) -> T {
        let found = tokio::time::timeout(timeout, async {
            loop {
                let arrived = self.arrived.notified();
                tokio::pin!(arrived);
                arrived.as_mut().enable();
                if let Some(found) = self.seen.lock().unwrap().iter().find(|v| matches(v)) {
                    return found.clone();
                }
                arrived.await;
            }
        })
        .await;
        found.unwrap_or_else(|_| {
            panic!(
                "nothing seen in {timeout:?} matched; seen so far: {}",
                self.seen.lock().unwrap().len()
            )
        })
    }
}

/// A clock a test moves by hand: time passes only when it says so, and waits end then.
pub struct ManualClock {
    now: Mutex<SystemTime>,
    sleepers: Mutex<Vec<(SystemTime, oneshot::Sender<()>)>>,
    changed: Notify,
    advanced: AtomicBool,
}

impl ManualClock {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            now: Mutex::new(SystemTime::now()),
            sleepers: Mutex::new(Vec::new()),
            changed: Notify::new(),
            advanced: AtomicBool::new(false),
        })
    }

    pub fn advance(&self, by: Duration) {
        let now = {
            let mut now = self.now.lock().unwrap();
            *now += by;
            *now
        };
        self.advanced.store(true, Ordering::SeqCst);
        let mut sleepers = self.sleepers.lock().unwrap();
        let mut waiting = Vec::new();
        for (at, wake) in sleepers.drain(..) {
            if at <= now {
                let _ = wake.send(());
            } else {
                waiting.push((at, wake));
            }
        }
        *sleepers = waiting;
    }

    /// Waits until at least `count` waits are pending on this clock.
    pub async fn when_sleeping(&self, count: usize) {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if self
                    .sleepers
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|(_, w)| !w.is_closed())
                    .count()
                    >= count
                {
                    return;
                }
                tokio::select! {
                    () = changed => {}
                    () = tokio::time::sleep(Duration::from_millis(20)) => {}
                }
            }
        })
        .await
        .expect("the waits were never made");
    }
}

impl Clock for ManualClock {
    fn now(&self) -> SystemTime {
        *self.now.lock().unwrap()
    }

    fn sleep(&self, duration: Duration) -> Sleep {
        let at = self.now() + duration;
        let (wake, woken) = oneshot::channel();
        self.sleepers.lock().unwrap().push((at, wake));
        self.changed.notify_waiters();
        Box::pin(async move {
            let _ = woken.await;
        })
    }
}

/// Runs `body` and gives it a chance to finish within `timeout`.
pub async fn within<T>(timeout: Duration, body: impl Future<Output = T>) -> T {
    tokio::time::timeout(timeout, body)
        .await
        .unwrap_or_else(|_| panic!("did not finish within {timeout:?}"))
}
