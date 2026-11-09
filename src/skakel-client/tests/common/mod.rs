//! What the integration tests share: a bench of real Skakel servers (`skakel-server`, in this
//! process, on loopback), wired the way an app wires one, with a test hub, a test stream type and
//! a pretend serial port. Everything is on loopback.

#![allow(dead_code)]

use std::collections::HashMap;
use std::future::Future;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::routing::get;
use serde_json::{Value, json};
use skakel_client::{Clock, Credentials, Pins, Sleep, Url};
use skakel_serial::{ClientMessage, ErrorCode, LineSettings, ModemStatus, ServerMessage};
use skakel_server::{
    Approval, BoxFuture, CertificateSwitch, HubCall, HubError, HubHandler, InMemoryStore,
    SkakelServer, SkakelServerBuilder, StreamHandler, StreamMessage, StreamOpen, StreamRequest,
    StreamSession,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Notify, oneshot};

/// The servers a test started. Dropping it stops them.
pub struct Bench {
    stores: HashMap<String, Arc<InMemoryStore>>,
    servers: HashMap<u64, Running>,
    next_id: u64,
}

struct Running {
    server: SkakelServer,
    store: String,
    udp: Option<u16>,
}

/// A server the bench started.
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

impl Bench {
    pub fn new() -> Self {
        Self {
            stores: HashMap::new(),
            servers: HashMap::new(),
            next_id: 0,
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
        let state = self
            .stores
            .entry(store.to_owned())
            .or_insert_with(|| Arc::new(InMemoryStore::new()))
            .clone();
        let server = start(state, tcp.unwrap_or(0), udp).await;
        self.next_id += 1;
        let started = Server {
            id: self.next_id,
            port: server.local_addr().port(),
            fingerprint: server.fingerprint(),
        };
        self.servers.insert(
            started.id,
            Running {
                server,
                store: store.to_owned(),
                udp,
            },
        );
        started
    }

    fn running(&self, server: &Server) -> &SkakelServer {
        &self
            .servers
            .get(&server.id)
            .expect("the server runs")
            .server
    }

    pub async fn stop(&mut self, server: &Server) {
        if let Some(running) = self.servers.remove(&server.id) {
            running.server.shutdown().await;
        }
    }

    /// Ends every hub connection and stream as a stopping server does, and starts the server
    /// again in the same state on the same port, so a link can connect again.
    pub async fn end_all(&mut self, server: &Server) {
        let running = self.servers.remove(&server.id).expect("the server runs");
        let state = self.stores[&running.store].clone();
        running.server.shutdown().await;
        let again = start(state, server.port, running.udp).await;
        self.servers.insert(
            server.id,
            Running {
                server: again,
                store: running.store,
                udp: running.udp,
            },
        );
    }

    pub async fn register(&mut self, server: &Server) -> Credentials {
        let client = self
            .running(server)
            .clients()
            .register("bench-1")
            .await
            .unwrap();
        Credentials::new(client.client_id, client.client_secret)
    }

    /// The pairing requests waiting on the server, as (id, client name).
    pub async fn requests(&mut self, server: &Server) -> Vec<(String, String)> {
        self.running(server)
            .pairing()
            .overview()
            .await
            .requests
            .into_iter()
            .filter(|r| r.state == "waiting")
            .map(|r| (r.id, r.client_name))
            .collect()
    }

    /// Types the code on the server, as a person would. What came of it.
    pub async fn approve(&mut self, server: &Server, request: &str, code: &str) -> Approval {
        self.running(server)
            .pairing()
            .approve(request, code)
            .await
            .unwrap()
    }

    /// Refuses a pairing request. False when it was not waiting.
    pub async fn deny(&mut self, server: &Server, request: &str) -> bool {
        self.running(server).pairing().deny(request).await
    }

    pub async fn revoke(&mut self, server: &Server, client: &str) -> bool {
        self.running(server).clients().revoke(client).await.unwrap()
    }

    pub async fn rotate(&mut self, server: &Server, client: &str) -> String {
        self.running(server)
            .clients()
            .rotate_secret(client)
            .await
            .unwrap()
            .expect("the client exists")
    }

    /// Prepares the next certificate. Its fingerprint.
    pub async fn prepare(&mut self, server: &Server) -> String {
        self.running(server)
            .keys()
            .prepare_next_certificate()
            .await
            .unwrap()
            .expect("a next certificate")
    }

    pub async fn switch(&mut self, server: &Server) -> CertificateSwitch {
        self.running(server)
            .keys()
            .switch_certificate()
            .await
            .unwrap()
            .expect("a prepared certificate to switch to")
    }

    pub async fn cancel(&mut self, server: &Server) -> bool {
        self.running(server)
            .keys()
            .cancel_next_certificate()
            .await
            .unwrap()
    }

    /// The server's clients, as (id, name, has a next certificate).
    pub async fn clients(&mut self, server: &Server) -> Vec<(String, String, bool)> {
        self.running(server)
            .clients()
            .all()
            .into_iter()
            .map(|c| (c.id, c.name, c.has_next_certificate))
            .collect()
    }
}

async fn start(store: Arc<InMemoryStore>, tcp: u16, udp: Option<u16>) -> SkakelServer {
    let mut builder = SkakelServerBuilder::new("test-app", "1.2.3", store)
        .name("bench")
        .listen(SocketAddr::from(([127, 0, 0, 1], tcp)))
        .discovery(udp.is_some())
        .hub("hub", TestHub)
        .stream("echo", echo())
        .stream("serial", pretend_serial())
        // A stream type whose server never answers the upgrade.
        .routes(Router::new().route(
            &format!("{}/stall", skakel_protocol::STREAMS_PATH),
            get(std::future::pending::<()>),
        ));
    if let Some(udp) = udp {
        builder = builder
            .discovery_bind("127.0.0.1".parse().unwrap())
            .discovery_port(udp);
    }
    builder.start().await.expect("the server starts")
}

/// An app's hub, as small as one gets.
struct TestHub;

impl HubHandler for TestHub {
    fn invoke(&self, call: HubCall) -> BoxFuture<'_, Result<Option<Value>, HubError>> {
        Box::pin(async move {
            let text = call.arguments.first().and_then(Value::as_str).unwrap_or("");
            match call.target.as_str() {
                "Greet" => {
                    call.connection.send(
                        "Greeted",
                        vec![json!(format!("{}: {}", call.connection.client_id, text))],
                    )?;
                    Ok(None)
                }
                "Echo" => Ok(Some(json!(text))),
                "Connection" => Ok(Some(json!(call.connection.connection_id))),
                other => Err(HubError::new(format!("There is no method {other}."))),
            }
        })
    }
}

/// The test stream type. The query names a target: none is 422, `missing` 404, `busy` 409,
/// `vanish` opens and closes at once with 4004, anything else echoes what it receives.
fn echo() -> StreamHandler {
    Arc::new(|request: StreamRequest| -> BoxFuture<'static, StreamOpen> {
        Box::pin(async move {
            match request.query_value("target").unwrap_or("") {
                "" => StreamOpen::Invalid("Say which target, as ?target=<name>.".into()),
                "missing" => StreamOpen::NotFound("There is no target called missing.".into()),
                "busy" => StreamOpen::InUse("bench-2 holds busy.".into()),
                "vanish" => StreamOpen::accept(|session: StreamSession| async move {
                    session
                        .close(skakel_protocol::CLOSE_TARGET_GONE, "unplugged")
                        .await;
                }),
                _ => StreamOpen::accept(|mut session: StreamSession| async move {
                    while let Some(message) = session.recv().await {
                        if session.send(message).await.is_err() {
                            return;
                        }
                    }
                }),
            }
        })
    })
}

/// A rate the pretend port cannot do.
pub const UNSUPPORTED_BAUD: i32 = 12_345;
/// A change to this rate is never answered.
pub const SILENT_BAUD: i32 = 54_321;
/// A change to this rate is answered after a second.
pub const SLOW_BAUD: i32 = 4800;

/// A serial port as an app would serve it, with the port played by a loopback: bytes sent come
/// back. `COM1` opens; `fault` opens and then reports a fault (4100); `busy` is 409; no port is
/// 422; anything else 404. Setting DTR raises DSR and DCD.
fn pretend_serial() -> StreamHandler {
    Arc::new(|request: StreamRequest| -> BoxFuture<'static, StreamOpen> {
        Box::pin(async move {
            let port = request.query_value("port").unwrap_or("").to_owned();
            match port.as_str() {
                "" => StreamOpen::Invalid("Say which port, as ?port=<id>.".into()),
                "busy" => StreamOpen::InUse("bench-2 holds busy.".into()),
                "COM1" | "fault" => {
                    StreamOpen::accept(move |session| run_serial(session, port == "fault"))
                }
                _ => StreamOpen::NotFound(format!("There is no port {port}.")),
            }
        })
    })
}

async fn run_serial(mut session: StreamSession, fault: bool) {
    let mut settings = LineSettings {
        baud: 9600,
        data_bits: 8,
        parity: skakel_serial::Parity::None,
        stop_bits: skakel_serial::StopBits::One,
        flow_control: skakel_serial::FlowControl::None,
    };
    let opened = ServerMessage::Opened {
        line_settings: settings,
        modem_status: ModemStatus {
            cts: true,
            dsr: false,
            dcd: false,
            ri: false,
        },
    };
    if session.send_text(opened.to_json()).await.is_err() {
        return;
    }
    if fault {
        session
            .close(
                skakel_serial::CLOSE_PORT_FAULT,
                "The port reported a fault.",
            )
            .await;
        return;
    }
    while let Some(message) = session.recv().await {
        let answer = match message {
            StreamMessage::Binary(data) => {
                if session.send_binary(data).await.is_err() {
                    return;
                }
                continue;
            }
            StreamMessage::Text(text) => match ClientMessage::parse(&text) {
                Some(ClientMessage::LineSettings(change)) if change.baud == UNSUPPORTED_BAUD => {
                    Some(ServerMessage::Error {
                        code: ErrorCode::Unsupported,
                        detail: Some(format!("This port cannot run at {UNSUPPORTED_BAUD} baud.")),
                    })
                }
                Some(ClientMessage::LineSettings(change)) if change.baud == SILENT_BAUD => None,
                Some(ClientMessage::LineSettings(change)) => {
                    if change.baud == SLOW_BAUD {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    settings = change;
                    Some(ServerMessage::LineSettings(settings))
                }
                Some(ClientMessage::ModemLines { dtr: Some(dtr), .. }) => {
                    Some(ServerMessage::ModemStatus(ModemStatus {
                        cts: true,
                        dsr: dtr,
                        dcd: dtr,
                        ri: false,
                    }))
                }
                _ => None,
            },
        };
        if let Some(answer) = answer
            && session.send_text(answer.to_json()).await.is_err()
        {
            return;
        }
    }
}

/// A server of another protocol version, as far as a client gets with one before it stops: it
/// answers `/skakel/info` with `versions`, refuses everything else with 404, and counts what else
/// was asked. Its certificate is its own, self-signed.
pub struct OtherVersion {
    pub port: u16,
    pub fingerprint: String,
    others: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl OtherVersion {
    pub async fn start(versions: &[u32]) -> Self {
        let signing = rcgen::KeyPair::generate().unwrap();
        let certificate = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
            .unwrap()
            .self_signed(&signing)
            .unwrap();
        let der = certificate.der().clone();
        let fingerprint = skakel_protocol::fingerprints::of_der(&der);
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(signing.serialize_der().into());
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der], key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let info = json!({
            "name": "elsewhere",
            "app": { "id": "test-app", "version": "9.0.0" },
            "versions": versions,
        })
        .to_string();
        let others = Arc::new(AtomicUsize::new(0));
        let counted = others.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let info = info.clone();
                let counted = counted.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        match tls.read(&mut byte).await {
                            Ok(1) => head.push(byte[0]),
                            _ => return,
                        }
                    }
                    let head = String::from_utf8_lossy(&head);
                    let path = head.split(' ').nth(1).unwrap_or("");
                    let (status, body) = if path == skakel_protocol::INFO_PATH {
                        ("200 OK", info.as_str())
                    } else {
                        counted.fetch_add(1, Ordering::SeqCst);
                        ("404 Not Found", "")
                    };
                    let answer = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = tls.write_all(answer.as_bytes()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        Self {
            port,
            fingerprint,
            others,
            task,
        }
    }

    pub fn address(&self) -> Url {
        Url::parse(&format!("https://127.0.0.1:{}/", self.port)).unwrap()
    }

    pub fn pins(&self) -> Pins {
        Pins::new(&self.fingerprint).unwrap()
    }

    /// How many requests other than `/skakel/info` it was sent.
    pub fn other_requests(&self) -> usize {
        self.others.load(Ordering::SeqCst)
    }
}

impl Drop for OtherVersion {
    fn drop(&mut self) {
        self.task.abort();
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
