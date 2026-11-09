//! The server: its builder, its listener and what the app holds on to.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use std::convert::Infallible;

use axum::Router;
use axum::http::{Request, Response};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use rustls::ServerConfig;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use skakel_discovery::MAX_APP_VERSION_LENGTH;
use skakel_proto::v2::control_service_server::ControlServiceServer;
use skakel_proto::v2::stream_service_server::StreamServiceServer;
use skakel_protocol::{
    CONTROL_MESSAGE_LIMIT, KEEP_ALIVE_INTERVAL, KEEP_ALIVE_TIMEOUT, Reason, STREAM_MESSAGE_LIMIT,
    SkakelApp, is_app_id, is_app_service_name, is_stream_type,
};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tonic::body::Body;
use tonic::server::NamedService;
use tonic::service::RoutesBuilder;
use tower_service::Service;

use crate::control::Control;
use crate::discovery::{self, Announcement};
use crate::error::ServerError;
use crate::events::{Events, ServerEvent};
use crate::grpc::{Guarded, is_grpc};
use crate::http::{self, looks_like_tls, plain_http_answer};
use crate::limits::Limits;
use crate::pairing::{Pairing, PairingOverview};
use crate::sessions::Sessions;
use crate::state::{CertificateSwitch, ClientView, KeysView, NewClient, ServerState};
use crate::store::SkakelStore;
use crate::streams::{StreamHandler, Streams};

/// How long a client has to start a TLS handshake, and to finish one.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a client has to send the headers of a request.
const HEADER_TIMEOUT: Duration = Duration::from_secs(30);
/// How long connections get to finish after the server stops.
const STOP_GRACE: Duration = Duration::from_secs(3);
/// How often the replaced signing keys that ran out are dropped.
const PRUNE_INTERVAL: Duration = Duration::from_secs(60);

/// What the server's handlers share.
pub(crate) struct Shared {
    pub name: String,
    pub app: SkakelApp,
    pub state: Arc<ServerState>,
    pub limits: Limits,
    pub pairing: Pairing,
    pub sessions: Arc<Sessions>,
    pub streams: HashMap<String, StreamHandler>,
    pub token_lifetime: Duration,
}

type Callback = Box<dyn Fn(&ServerEvent) + Send + Sync>;

/// Adds an app's service to the routes, behind the token check, once the server's state exists.
type AddService = Box<dyn FnOnce(&mut RoutesBuilder, Arc<Shared>) + Send>;

/// An app's gRPC service, waiting for the server's state to be put in front of it.
struct AppService {
    name: &'static str,
    add: AddService,
}

/// Builds a Skakel server. Give it an app id and version and a store, say where to listen, add
/// the app's gRPC services, stream types and HTTPS routes, and [`start`](Self::start) it.
pub struct SkakelServerBuilder {
    app_id: String,
    app_version: String,
    store: Arc<dyn SkakelStore>,
    name: String,
    listen: SocketAddr,
    discovery: bool,
    discovery_bind: IpAddr,
    discovery_port: Option<u16>,
    token_requests_per_minute: u32,
    pair_requests_per_minute: u32,
    keep_client_secrets: bool,
    certificate_host_name: String,
    token_lifetime: Duration,
    services: Vec<AppService>,
    streams: HashMap<String, StreamHandler>,
    routes: Option<Router>,
    callbacks: Vec<Callback>,
}

fn machine_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "localhost".to_owned())
}

impl SkakelServerBuilder {
    /// A builder for the app `app_id` (1 to 32 of `a-z`, `0-9` and `-`) at `app_version`,
    /// keeping its state in `store`.
    pub fn new(
        app_id: impl Into<String>,
        app_version: impl Into<String>,
        store: impl SkakelStore,
    ) -> Self {
        let machine = machine_name();
        Self {
            app_id: app_id.into(),
            app_version: app_version.into(),
            store: Arc::new(store),
            name: machine.clone(),
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            discovery: true,
            discovery_bind: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            discovery_port: None,
            token_requests_per_minute: 60,
            pair_requests_per_minute: 120,
            keep_client_secrets: false,
            certificate_host_name: machine,
            token_lifetime: skakel_protocol::ACCESS_TOKEN_LIFETIME,
            services: vec![],
            streams: HashMap::new(),
            routes: None,
            callbacks: vec![],
        }
    }

    /// The name people know the server by. Defaults to the machine's name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// The address and TCP port to serve HTTPS on. A port of 0 takes a free one; discovery
    /// announces the port actually bound. Defaults to every IPv4 address and a free port.
    pub fn listen(mut self, address: SocketAddr) -> Self {
        self.listen = address;
        self
    }

    /// Whether to answer discovery probes. On by default.
    pub fn discovery(mut self, enabled: bool) -> Self {
        self.discovery = enabled;
        self
    }

    /// The UDP port discovery answers on. Defaults to the TCP port. Needs to be the app's port
    /// for clients to find the server, so it is only set apart for tests.
    pub fn discovery_port(mut self, port: u16) -> Self {
        self.discovery_port = Some(port);
        self
    }

    /// The local address the discovery socket binds. Defaults to every IPv4 address, which is
    /// what receiving broadcast probes takes.
    pub fn discovery_bind(mut self, address: IpAddr) -> Self {
        self.discovery_bind = address;
        self
    }

    /// Token requests one address may make a minute. Defaults to 60.
    pub fn token_requests_per_minute(mut self, limit: u32) -> Self {
        self.token_requests_per_minute = limit;
        self
    }

    /// Pairing calls, polls included, one address may make a minute. Defaults to 120.
    pub fn pair_requests_per_minute(mut self, limit: u32) -> Self {
        self.pair_requests_per_minute = limit;
        self
    }

    /// Keeps each client's secret in the state, for an app that shows it again. Off by default:
    /// the state then holds only a hash.
    pub fn keep_client_secrets(mut self, keep: bool) -> Self {
        self.keep_client_secrets = keep;
        self
    }

    /// The host name in the certificate. Clients pin the fingerprint and ignore it.
    pub fn certificate_host_name(mut self, name: impl Into<String>) -> Self {
        self.certificate_host_name = name.into();
        self
    }

    /// How long the access tokens it issues last, at most the protocol's 30 minutes. For tests of
    /// what happens when a token runs out.
    #[doc(hidden)]
    pub fn token_lifetime(mut self, lifetime: Duration) -> Self {
        self.token_lifetime = lifetime;
        self
    }

    /// Adds one of the app's own gRPC services, such as the server tonic generated from the app's
    /// `.proto` file, beside Skakel's on the same port and connections. Its package must not be
    /// `skakel` or start with `skakel.`.
    ///
    /// Skakel checks every call's bearer token, and the client's generation, before the service
    /// sees it, and refuses one without a current token with `TOKEN_REFUSED`. A call that gets
    /// through carries a [`ClientPrincipal`](crate::ClientPrincipal) in its extensions, so the app
    /// knows which client called. When that client is revoked or its secret rotated, or the server
    /// stops, Skakel ends its calls still running with `REVOKED`, `ROTATED` or `STOPPING`. A token
    /// that expires does not end a call already running.
    pub fn grpc_service<S>(mut self, service: S) -> Self
    where
        S: NamedService
            + Service<Request<Body>, Response = Response<Body>, Error = Infallible>
            + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static,
    {
        self.services.push(AppService {
            name: S::NAME,
            add: Box::new(move |routes, shared| {
                routes.add_service(Guarded::new(service, shared, true));
            }),
        });
        self
    }

    /// Adds a stream type, opened with `StreamService.Open` and this type in its `open` frame.
    pub fn stream(mut self, stream_type: impl Into<String>, handler: StreamHandler) -> Self {
        self.streams.insert(stream_type.into(), handler);
        self
    }

    /// Adds the app's own routes. They sit beside Skakel's, and can take the bearer token with
    /// the [`ClientPrincipal`](crate::ClientPrincipal) extractor. Paths under `/skakel/` are
    /// Skakel's own.
    pub fn routes(mut self, routes: Router) -> Self {
        self.routes = Some(routes);
        self
    }

    /// Calls `callback` for everything that happens on the server, such as a pairing request
    /// waiting for a person. It runs on the server's own tasks, so it must not block; send what
    /// it gets to the app's UI thread.
    pub fn on_event(mut self, callback: impl Fn(&ServerEvent) + Send + Sync + 'static) -> Self {
        self.callbacks.push(Box::new(callback));
        self
    }

    /// Calls `callback` with the pairing requests waiting for a person, whenever they change.
    /// The app shows them and calls [`Pairing::approve`] or [`Pairing::deny`].
    pub fn on_pairing(self, callback: impl Fn(&PairingOverview) + Send + Sync + 'static) -> Self {
        self.on_event(move |event| {
            if let ServerEvent::Pairing(overview) = event {
                callback(overview);
            }
        })
    }

    fn problems(&self) -> Vec<String> {
        let mut problems = vec![];
        if !is_app_id(&self.app_id) {
            problems.push("The app id must be 1 to 32 of a-z, 0-9 and -.".to_owned());
        }
        if self.app_version.trim().is_empty()
            || self.app_version.encode_utf16().count() > MAX_APP_VERSION_LENGTH
        {
            problems.push(format!(
                "The app version must be 1 to {MAX_APP_VERSION_LENGTH} characters."
            ));
        }
        if self.name.trim().is_empty() {
            problems.push("The name must not be empty.".to_owned());
        }
        if self.token_requests_per_minute < 1 || self.pair_requests_per_minute < 1 {
            problems.push("The rate limits must allow at least one request a minute.".to_owned());
        }
        if self.certificate_host_name.trim().is_empty() {
            problems.push("The certificate host name must not be empty.".to_owned());
        }
        for (i, service) in self.services.iter().enumerate() {
            if !is_app_service_name(service.name) {
                problems.push(format!(
                    "The gRPC service '{}' must be in a package of the app's own, not skakel or one under it.",
                    service.name
                ));
            } else if self.services[..i].iter().any(|s| s.name == service.name) {
                problems.push(format!(
                    "The gRPC service '{}' was added twice.",
                    service.name
                ));
            }
        }
        for stream_type in self.streams.keys() {
            if !is_stream_type(stream_type) {
                problems.push(format!(
                    "The stream type '{stream_type}' must be from a-z, 0-9 and -."
                ));
            }
        }
        problems
    }

    /// Starts the server: loads or makes its keys, binds the port, starts answering discovery
    /// and serving.
    pub async fn start(self) -> Result<SkakelServer, ServerError> {
        let problems = self.problems();
        if !problems.is_empty() {
            return Err(ServerError::Options(problems));
        }
        let events = Events::new(self.callbacks);
        let state = ServerState::start(
            self.store,
            self.keep_client_secrets,
            self.certificate_host_name,
            self.app_id.clone(),
            events,
        )
        .await?;
        let pairing = Pairing::new(state.clone());
        pairing.spawn_sweeper();
        let sessions = Sessions::new(state.clone());
        sessions.spawn_watch();
        spawn_pruner(&state);

        let app = SkakelApp {
            id: self.app_id,
            version: self.app_version,
        };
        let name = self.name;
        let shared = Arc::new(Shared {
            name: name.clone(),
            app: app.clone(),
            state: state.clone(),
            limits: Limits::new(
                self.token_requests_per_minute,
                self.pair_requests_per_minute,
            ),
            pairing: pairing.clone(),
            sessions: sessions.clone(),
            streams: self.streams,
            token_lifetime: self.token_lifetime,
        });

        let mut router = http::router(shared.clone());
        if let Some(routes) = self.routes {
            router = router.merge(routes);
        }
        let https = http::guard(router, shared.clone());
        let grpc = grpc_router(&shared, self.services);

        let listener = TcpListener::bind(self.listen)
            .await
            .map_err(ServerError::Bind)?;
        let local_addr = listener.local_addr().map_err(ServerError::Bind)?;
        let (stop, stopped) = watch::channel(false);
        let mut tasks = vec![];

        let mut discovery_addr = None;
        if self.discovery {
            let port = self.discovery_port.unwrap_or(local_addr.port());
            // A port that is not free costs only discovery; clients can still enter the address.
            if let Ok(socket) = UdpSocket::bind(SocketAddr::new(self.discovery_bind, port)).await {
                discovery_addr = socket.local_addr().ok();
                let announcement = Announcement {
                    name,
                    port: local_addr.port(),
                    app,
                };
                tasks.push(tokio::spawn(discovery::answer(
                    socket,
                    state.clone(),
                    announcement,
                    stopped.clone(),
                )));
            }
        }

        let acceptor = tls_acceptor(&state)?;
        tasks.push(tokio::spawn(accept_loop(
            listener,
            acceptor,
            Routers { https, grpc },
            stopped.clone(),
        )));

        Ok(SkakelServer {
            shared,
            local_addr,
            discovery_addr,
            stop,
            tasks,
        })
    }
}

/// Skakel's control and stream services and the app's, each behind the token check.
fn grpc_router(shared: &Arc<Shared>, services: Vec<AppService>) -> Router {
    let mut routes = RoutesBuilder::default();
    let control = ControlServiceServer::new(Control {
        shared: shared.clone(),
    })
    .max_decoding_message_size(CONTROL_MESSAGE_LIMIT)
    .max_encoding_message_size(CONTROL_MESSAGE_LIMIT);
    routes.add_service(Guarded::new(control, shared.clone(), false));
    let streams = StreamServiceServer::new(Streams {
        shared: shared.clone(),
    })
    .max_decoding_message_size(STREAM_MESSAGE_LIMIT)
    .max_encoding_message_size(STREAM_MESSAGE_LIMIT);
    routes.add_service(Guarded::new(streams, shared.clone(), false));
    for service in services {
        (service.add)(&mut routes, shared.clone());
    }
    routes.routes().into_axum_router()
}

fn spawn_pruner(state: &Arc<ServerState>) {
    let weak = Arc::downgrade(state);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(PRUNE_INTERVAL);
        loop {
            tick.tick().await;
            let Some(state) = weak.upgrade() else { return };
            let _ = state.prune_retired_keys().await;
        }
    });
}

/// A running Skakel server.
pub struct SkakelServer {
    shared: Arc<Shared>,
    local_addr: SocketAddr,
    discovery_addr: Option<SocketAddr>,
    stop: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl SkakelServer {
    /// The address HTTPS is served on, with the port actually bound.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The UDP address discovery answers on, when it is running.
    pub fn discovery_addr(&self) -> Option<SocketAddr> {
        self.discovery_addr
    }

    /// The fingerprint of the certificate the server presents.
    pub fn fingerprint(&self) -> String {
        self.shared.state.fingerprint()
    }

    /// The registered clients.
    pub fn clients(&self) -> Clients {
        Clients {
            state: self.shared.state.clone(),
        }
    }

    /// The certificates and the token signing key.
    pub fn keys(&self) -> Keys {
        Keys {
            state: self.shared.state.clone(),
        }
    }

    /// The pairing requests.
    pub fn pairing(&self) -> Pairing {
        self.shared.pairing.clone()
    }

    /// What happens on the server, as a stream the app can read. A slow reader misses events
    /// rather than slowing the server.
    pub fn subscribe(&self) -> broadcast::Receiver<ServerEvent> {
        self.shared.state.events.subscribe()
    }

    /// How many calls a client has running that stay open: control calls, streams and calls to
    /// the app's own services.
    pub fn open_sessions(&self, client_id: &str) -> usize {
        self.shared.sessions.count_for(client_id)
    }

    /// Stops the server. Control calls are told `closing` and every call still running ends with
    /// `STOPPING`, the listener closes, and connections have a few seconds to finish.
    pub async fn shutdown(mut self) {
        self.shared.sessions.end_all(Reason::Stopping);
        // Time for the closing messages to leave before connections are asked to wind down.
        tokio::time::sleep(Duration::from_millis(200)).await;
        self.stop.send_replace(true);
        for task in self.tasks.drain(..) {
            let _ = tokio::time::timeout(STOP_GRACE + Duration::from_secs(1), task).await;
        }
    }
}

impl Drop for SkakelServer {
    fn drop(&mut self) {
        self.shared.sessions.end_all(Reason::Stopping);
        self.stop.send_replace(true);
    }
}

/// The registered clients.
#[derive(Clone)]
pub struct Clients {
    state: Arc<ServerState>,
}

impl Clients {
    /// Every client.
    pub fn all(&self) -> Vec<ClientView> {
        self.state.clients()
    }

    /// Registers a client without pairing, for an app that makes its own. The name loses control
    /// and format characters and the spaces around it; an empty one is an error.
    pub async fn register(&self, name: &str) -> Result<NewClient, ServerError> {
        self.state.register_client(name).await
    }

    /// Gives a client a new secret. Its tokens from before stop working, and its calls still
    /// running end at once with `ROTATED`. `None` for an unknown client.
    pub async fn rotate_secret(&self, client_id: &str) -> Result<Option<String>, ServerError> {
        self.state.rotate_secret(client_id).await
    }

    /// Removes a client. Its tokens stop working, and its calls still running end at once with
    /// `REVOKED`. False for an
    /// unknown client.
    pub async fn revoke(&self, client_id: &str) -> Result<bool, ServerError> {
        self.state.revoke_client(client_id).await
    }

    /// The name of a client.
    pub fn name_of(&self, client_id: &str) -> Option<String> {
        self.state.find(client_id).map(|c| c.name)
    }

    /// The secret of a client, when the server was told to keep them.
    pub fn secret_of(&self, client_id: &str) -> Option<String> {
        self.state.find(client_id).and_then(|c| c.secret)
    }
}

/// The server's certificates and its token signing key.
#[derive(Clone)]
pub struct Keys {
    state: Arc<ServerState>,
}

impl Keys {
    /// The certificate the server presents, DER.
    pub fn certificate_der(&self) -> Vec<u8> {
        self.state.loaded().certified.cert[0].as_ref().to_vec()
    }

    /// Its fingerprint.
    pub fn fingerprint(&self) -> String {
        self.state.fingerprint()
    }

    /// The fingerprint of the next certificate, during a handover.
    pub fn next_fingerprint(&self) -> Option<String> {
        self.state.loaded().next_fingerprint.clone()
    }

    /// Both fingerprints, the signing key and what else is in use.
    pub fn view(&self) -> KeysView {
        self.state.keys()
    }

    /// Prepares the next certificate. Clients are told on the control channel; the server goes on
    /// presenting the current one. Returns the next fingerprint, or `None` when one is already
    /// prepared.
    pub async fn prepare_next_certificate(&self) -> Result<Option<String>, ServerError> {
        self.state.prepare_certificate().await
    }

    /// Drops the prepared certificate. Clients forget it. False when there was none.
    pub async fn cancel_next_certificate(&self) -> Result<bool, ServerError> {
        self.state.cancel_certificate().await
    }

    /// Presents the prepared certificate from now on. `None` when none was prepared; otherwise
    /// the names of the clients that never stored it, who have to pair again.
    pub async fn switch_certificate(&self) -> Result<Option<CertificateSwitch>, ServerError> {
        self.state.switch_certificate().await
    }

    /// Makes a new token signing key. Tokens of the old one stay good until they would have
    /// expired. Returns the new key's id.
    pub async fn rotate_signing_key(&self) -> Result<String, ServerError> {
        self.state.rotate_signing_key().await
    }
}

struct Resolver(Arc<ServerState>);

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Resolver")
    }
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.loaded().certified.clone())
    }
}

fn tls_acceptor(state: &Arc<ServerState>) -> Result<TlsAcceptor, ServerError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| ServerError::State(format!("TLS could not be set up: {e}")))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Resolver(state.clone())));
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    // No session resumption. A resumed session shows the client no certificate, and a client that follows
    // a handover proves the new certificate by the one a new connection presents (docs/protocol.md,
    // "Certificates"). rustls would also resume a session made under the old certificate after the
    // switch. A full handshake on a P-256 certificate costs next to nothing.
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// The HTTPS routes and the gRPC services, which share the port and its connections.
#[derive(Clone)]
struct Routers {
    https: Router,
    grpc: Router,
}

async fn accept_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    routers: Routers,
    mut stopped: watch::Receiver<bool>,
) {
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = stopped.changed() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, remote)) => {
                    connections.spawn(serve_connection(
                        stream,
                        remote,
                        acceptor.clone(),
                        routers.clone(),
                        stopped.clone(),
                    ));
                }
                // A connection that was reset before it was taken is its own affair.
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            },
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    drop(listener);
    let _ = tokio::time::timeout(STOP_GRACE, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    connections.abort_all();
}

async fn serve_connection(
    mut stream: TcpStream,
    remote: SocketAddr,
    acceptor: TlsAcceptor,
    routers: Routers,
    mut stopped: watch::Receiver<bool>,
) {
    let _ = stream.set_nodelay(true);
    let mut first = [0u8; 1];
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.peek(&mut first)).await {
        Ok(Ok(1)) if looks_like_tls(first[0]) => {}
        Ok(Ok(1)) => {
            // Plain HTTP on the HTTPS port: say so, in words, instead of hanging up.
            let _ = stream.write_all(&plain_http_answer()).await;
            let _ = stream.shutdown().await;
            return;
        }
        _ => return,
    }
    let Ok(Ok(tls)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await else {
        return;
    };
    let service = hyper::service::service_fn(move |mut request: hyper::Request<Incoming>| {
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(remote));
        // The content type tells a gRPC call; everything else is an HTTPS request.
        let mut router = if is_grpc(request.headers()) {
            routers.grpc.clone()
        } else {
            routers.https.clone()
        };
        async move { router.call(request).await }
    });
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT);
    // A PING after 15 seconds without a frame from the client, and the connection is dead when that
    // PING has no answer 15 seconds later: 30 seconds of silence in all. Pings from the client are
    // answered at any rate. Adaptive windows let a stream's flow-control window grow with the link,
    // beyond HTTP/2's 64 KiB start, which would hold a stream to 64 KiB per round trip.
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(KEEP_ALIVE_INTERVAL)
        .keep_alive_timeout(KEEP_ALIVE_TIMEOUT - KEEP_ALIVE_INTERVAL)
        .adaptive_window(true);
    let connection = builder.serve_connection_with_upgrades(TokioIo::new(tls), service);
    tokio::pin!(connection);
    tokio::select! {
        _ = connection.as_mut() => {}
        _ = stopped.changed() => {
            connection.as_mut().graceful_shutdown();
            let _ = tokio::time::timeout(STOP_GRACE, connection.as_mut()).await;
        }
    }
}
