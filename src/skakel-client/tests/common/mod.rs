//! What the integration tests share: a bench of real Skakel servers (`skakel-server`, in this
//! process, on loopback), wired the way an app wires one, with the app's own gRPC service and HTTPS
//! route, a test stream type, one that never answers, and a pretend serial port. Everything is on
//! loopback.

#![allow(dead_code)]

/// The app's own gRPC service, shared with the server's tests.
#[path = "../../../skakel-server/tests/common/greeter.rs"]
pub mod greeter;

use std::collections::HashMap;
use std::future::Future;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use axum::Router;
use axum::routing::get;
use serde_json::json;
use skakel_client::{Clock, Credentials, Pins, Sleep, Url};
use skakel_serial::{ClientMessage, ErrorCode, LineSettings, ModemStatus, ServerMessage};
use skakel_server::{
    Approval, CertificateSwitch, ClientPrincipal, InMemoryStore, SkakelServer, SkakelServerBuilder,
    StreamEnd, StreamMessage, StreamOpen, StreamRequest, StreamSession,
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

    /// A server whose tokens last `lifetime`, so the control calls they open end soon.
    pub async fn server_with_token_lifetime(&mut self, lifetime: Duration) -> Server {
        let state = Arc::new(InMemoryStore::new());
        self.stores.insert("short-tokens".to_owned(), state.clone());
        let server = start_with(state, 0, None, Some(lifetime), true).await;
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
                store: "short-tokens".to_owned(),
                udp: None,
            },
        );
        started
    }

    /// A server as an app builds it by default: it takes no pairing request until its app opens a
    /// window (see [`Bench::open_pairing_window`]).
    pub async fn server_with_pairing_closed(&mut self) -> Server {
        let state = Arc::new(InMemoryStore::new());
        self.stores.insert("closed".to_owned(), state.clone());
        let server = start_with(state, 0, None, None, false).await;
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
                store: "closed".to_owned(),
                udp: None,
            },
        );
        started
    }

    /// Opens the server's pairing window.
    pub fn open_pairing_window(&self, server: &Server) {
        self.running(server).open_pairing(Duration::from_secs(300));
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

    /// Ends every call as a stopping server does, and starts the server again in the same state on
    /// the same port, so a link can connect again.
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
            .certificates()
            .prepare_next_certificate()
            .await
            .unwrap()
            .expect("a next certificate")
    }

    pub async fn switch(&mut self, server: &Server) -> CertificateSwitch {
        self.running(server)
            .certificates()
            .switch_certificate()
            .await
            .unwrap()
            .expect("a prepared certificate to switch to")
    }

    pub async fn cancel(&mut self, server: &Server) -> bool {
        self.running(server)
            .certificates()
            .cancel_next_certificate()
            .await
            .unwrap()
    }

    /// The server's clients, as (id, name, has a next certificate).
    /// How many calls that stay open the client has running on the server.
    pub fn open_sessions(&self, server: &Server, client: &str) -> usize {
        self.running(server).open_sessions(client)
    }

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
    start_with(store, tcp, udp, None, true).await
}

async fn start_with(
    store: Arc<InMemoryStore>,
    tcp: u16,
    udp: Option<u16>,
    token_lifetime: Option<Duration>,
    pairing_open: bool,
) -> SkakelServer {
    let mut builder = SkakelServerBuilder::new("test-app", "1.2.3", store)
        .name("bench")
        .listen(SocketAddr::from(([127, 0, 0, 1], tcp)))
        .discovery(udp.is_some())
        .grpc_service(greeter::Greeter)
        .stream("echo", echo())
        .stream("serial", pretend_serial())
        // A stream type whose server never answers the open.
        .stream("stall", |_request: StreamRequest| {
            std::future::pending::<StreamOpen>()
        })
        // The app's own HTTPS endpoint, which takes the same token.
        .routes(Router::new().route("/app/whoami", get(whoami)));
    if let Some(lifetime) = token_lifetime {
        builder = builder.token_lifetime(lifetime);
    }
    if pairing_open {
        // A server as the tests use it: nobody has to open a pairing window first.
        builder = builder.pairing_always_open();
    }
    if let Some(udp) = udp {
        builder = builder
            .discovery_bind("127.0.0.1".parse().unwrap())
            .discovery_port(udp);
    }
    builder.start().await.expect("the server starts")
}

/// The app's own HTTPS endpoint: who the token belongs to.
async fn whoami(ClientPrincipal(principal): ClientPrincipal) -> String {
    principal.client_id
}

/// The test stream type. The target is text: none is `BAD_TARGET`, `missing` `NO_SUCH_TARGET`,
/// `busy` `IN_USE`, `vanish` opens and ends at once with `TARGET_GONE`, `sink` counts the data it
/// gets and, once the client ends its side, sends the count as a control frame (eight bytes,
/// big-endian), anything else echoes what it receives.
fn echo() -> impl skakel_server::StreamHandler {
    |request: StreamRequest| async move {
        match std::str::from_utf8(&request.target).unwrap_or("") {
            "" => StreamOpen::BadTarget("Say which target.".into()),
            "missing" => StreamOpen::NotFound("There is no target called missing.".into()),
            "busy" => StreamOpen::InUse("bench-2 holds busy.".into()),
            "vanish" => StreamOpen::accept(|session: StreamSession| async move {
                session.end(StreamEnd::target_gone("unplugged")).await;
            }),
            "sink" => StreamOpen::accept(|mut session: StreamSession| async move {
                let mut total = 0u64;
                while let Some(message) = session.recv().await {
                    if let StreamMessage::Data(data) = message {
                        total += data.len() as u64;
                    }
                }
                let _ = session.send_control(total.to_be_bytes().to_vec()).await;
            }),
            _ => StreamOpen::accept(|mut session: StreamSession| async move {
                while let Some(message) = session.recv().await {
                    if session.send(message).await.is_err() {
                        return;
                    }
                }
            }),
        }
    }
}

/// A rate the pretend port cannot do.
pub const UNSUPPORTED_BAUD: u32 = 12_345;
/// A change to this rate is never answered.
pub const SILENT_BAUD: u32 = 54_321;
/// A change to this rate is answered after a second.
pub const SLOW_BAUD: u32 = 4800;

/// A serial port as an app would serve it, with the port played by a loopback: bytes sent come
/// back. `COM1` opens; `fault` opens and then reports a fault (`PORT_FAULT`); `busy` is `IN_USE`;
/// no port is `BAD_TARGET`; anything else `NO_SUCH_TARGET`. Setting DTR raises DSR and DCD.
fn pretend_serial() -> impl skakel_server::StreamHandler {
    |request: StreamRequest| async move {
        let port = skakel_serial::port_of(&request.target).unwrap_or_default();
        match port.as_str() {
            "" => StreamOpen::BadTarget("Say which port.".into()),
            "busy" => StreamOpen::InUse("bench-2 holds busy.".into()),
            "COM1" | "fault" => {
                StreamOpen::accept(move |session| run_serial(session, port == "fault"))
            }
            _ => StreamOpen::NotFound(format!("There is no port {port}.")),
        }
    }
}

async fn run_serial(mut session: StreamSession, fault: bool) {
    let mut settings = LineSettings {
        baud: 9600,
        data_bits: skakel_serial::DataBits::Eight,
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
    if session.send_control(opened.encode()).await.is_err() {
        return;
    }
    if fault {
        session
            .end(
                StreamEnd::aborted(skakel_serial::PORT_FAULT, "The port reported a fault.")
                    .unwrap(),
            )
            .await;
        return;
    }
    while let Some(message) = session.recv().await {
        let answer = match message {
            StreamMessage::Data(data) => {
                if session.send_data(data).await.is_err() {
                    return;
                }
                continue;
            }
            StreamMessage::Control(control) => match ClientMessage::decode(&control).ok() {
                Some(ClientMessage::LineSettings {
                    request_id,
                    settings: change,
                }) if change.baud == UNSUPPORTED_BAUD => Some(ServerMessage::Error {
                    request_id,
                    code: ErrorCode::Unsupported,
                    detail: Some(format!("This port cannot run at {UNSUPPORTED_BAUD} baud.")),
                }),
                Some(ClientMessage::LineSettings {
                    settings: change, ..
                }) if change.baud == SILENT_BAUD => None,
                Some(ClientMessage::LineSettings {
                    request_id,
                    settings: change,
                }) => {
                    if change.baud == SLOW_BAUD {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    settings = change;
                    Some(ServerMessage::LineSettings {
                        request_id,
                        settings,
                    })
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
            && session.send_control(answer.encode()).await.is_err()
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
        let fingerprint = skakel_wire::fingerprints::of_der(&der);
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
                    let (status, body) = if path == skakel_wire::INFO_PATH {
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
    wall: SystemTime,
    mono: Instant,
    elapsed: Mutex<Duration>,
    sleepers: Mutex<Vec<(Duration, oneshot::Sender<()>)>>,
    changed: Notify,
    advanced: AtomicBool,
}

impl ManualClock {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            wall: SystemTime::now(),
            mono: Instant::now(),
            elapsed: Mutex::new(Duration::ZERO),
            sleepers: Mutex::new(Vec::new()),
            changed: Notify::new(),
            advanced: AtomicBool::new(false),
        })
    }

    pub fn advance(&self, by: Duration) {
        let now = {
            let mut elapsed = self.elapsed.lock().unwrap();
            *elapsed += by;
            *elapsed
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
        self.wall + *self.elapsed.lock().unwrap()
    }

    fn instant(&self) -> Instant {
        self.mono + *self.elapsed.lock().unwrap()
    }

    fn sleep(&self, duration: Duration) -> Sleep {
        let at = *self.elapsed.lock().unwrap() + duration;
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

/// A TCP proxy on loopback in front of a server, which counts the connections made through it.
/// TLS passes through untouched, so the server's certificate is what the client sees.
pub struct CountingProxy {
    pub port: u16,
    count: Arc<AtomicUsize>,
    failing: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl CountingProxy {
    pub async fn start(to: u16) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let count = Arc::new(AtomicUsize::new(0));
        let counted = count.clone();
        let failing = Arc::new(AtomicUsize::new(0));
        let failures = failing.clone();
        let task = tokio::spawn(async move {
            while let Ok((mut inbound, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                if failures
                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                    .is_ok()
                {
                    // A connection that dies before the server sees anything.
                    continue;
                }
                tokio::spawn(async move {
                    let Ok(mut outbound) = tokio::net::TcpStream::connect(("127.0.0.1", to)).await
                    else {
                        return;
                    };
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                });
            }
        });
        Self {
            port,
            count,
            failing,
            task,
        }
    }

    /// Closes the next `n` connections made through it without passing them on.
    pub fn fail_next(&self, n: usize) {
        self.failing.store(n, Ordering::SeqCst);
    }

    pub fn address(&self) -> Url {
        Url::parse(&format!("https://127.0.0.1:{}/", self.port)).unwrap()
    }

    /// How many connections were made through it so far.
    pub fn connections(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }
}

impl Drop for CountingProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Records each status the link goes through, in order.
pub fn record_status(link: &skakel_client::Link) -> Recorder<skakel_client::LinkStatus> {
    let recorder = Recorder::new();
    let to = recorder.clone();
    let mut events = link.events();
    tokio::spawn(async move {
        while let Ok(event) = events.recv().await {
            if let skakel_client::LinkEvent::Status(status) = event {
                to.record(status);
            }
        }
    });
    recorder
}
