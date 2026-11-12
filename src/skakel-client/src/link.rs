//! A client's link to one server: HTTPS and gRPC pinned to the server's certificates, a token
//! client, the control channel, the app's own gRPC calls, and the streams. An app holds one per
//! server it is paired with.
//!
//! The app keeps the address, the pins and the credentials, and hands them in. What changes goes
//! back out two ways: [`Link::watch_status`], [`Link::watch_address`] and [`Link::watch_pins`]
//! hold the latest value, [`Link::events`] has each change in order, and a [`PinStore`] set with
//! [`Link::set_pin_store`] saves the pins during a certificate handover, which the link
//! acknowledges to the server only once the store has them.
//!
//! Once started, the link keeps the control channel up: it reads `/skakel/info` to check the
//! version, gets a token, opens a gRPC connection pinned to the certificate and calls
//! `ControlService.Connect`. Thirty seconds before the token runs out it gets a new one and calls
//! `Connect` again on the same connection, without saying so, and lets the old call go once the new
//! one has sent the certificates. When the connection drops it connects again, after a pause that
//! grows to a minute. Connections and `Connect` calls never start less than a second apart, and a
//! token is taken to last 2 to 30 minutes whatever the server says. A revoke or rotation on the
//! server ends it for good, as [`LinkState::Closed`], and so does the token endpoint refusing the
//! client's credentials.
//!
//! The app's own gRPC services are reached through [`Link::channel`], over the control channel's
//! connection with the link's token; each stream opens a connection of its own.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use ::http::{Method, StatusCode};
use skakel_proto::v2::control_service_client::ControlServiceClient;
use skakel_proto::v2::{
    Certificates, ClosingReason, ConnectRequest, ConnectResponse, HelloRequest,
    NextCertificateReceived, connect_request, connect_response,
};
use skakel_protocol::{
    ACCESS_TOKEN_LIFETIME, CONTROL_MESSAGE_LIMIT, INFO_PATH, Reason, SkakelHello, fingerprints,
    is_stream_type,
};
use skakel_serial::STREAM_TYPE;
use tokio::sync::{Notify, broadcast, mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tonic::body::Body;
use tonic::{Status, Streaming};
use url::Url;

use crate::browser::{Browser, Protection};
use crate::clock::{Clock, since};
use crate::events::{Events, StateWatch};
use crate::failure::{Error, Failure, FailureKind, Result, bad_answer, is_unreachable};
use crate::grpc::{self, Connection, call_failed, is_token_refused, reason_of};
use crate::http::{self, is_at};
use crate::info::{read_info_with, require_version};
use crate::moves::{PROOF_TIMEOUT, ServerMoves};
use crate::options::ClientOptions;
use crate::pins::{Credentials, Pins};
use crate::request::{HttpClient, RequestBuilder, Response};
use crate::serial::SerialConnection;
use crate::streams::{self, OpenResult, StreamConnection, StreamRefusalReason, with_token};
use crate::tokens::{Token, TokenClient};

/// The most of an answer from the app's own HTTPS endpoints that is read: 16 MiB.
const MAX_APP_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// How long before a token runs out the control call is renewed with a fresh one.
const REFRESH_AHEAD: Duration = Duration::from_secs(30);

/// The shortest time between two connections or two `Connect` calls.
const MIN_BACKOFF: Duration = Duration::from_secs(1);

const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// How long a connection has to have been up for the next pause to start from the shortest again.
/// A server that accepts the call and ends it at once keeps the pause growing.
const STABLE_AFTER: Duration = Duration::from_secs(30);

/// Messages waiting to go out on a control call.
const CONTROL_QUEUE: usize = 8;

/// What saving the pins may fail with.
pub type StoreError = Box<dyn std::error::Error + Send + Sync>;

/// What [`PinStore::save`] gives back.
pub type SaveFuture = Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send>>;

/// Where an app keeps the pins of a server, so a certificate handover survives a restart. The link
/// hands every change of its pins to it and tells the server it has the next certificate only once
/// `save` has returned `Ok`; a save that fails, or panics, is taken as not saved, and the server
/// says it again on the next connection.
///
/// Any `Fn(Pins) -> impl Future<Output = Result<(), E>>` is one:
///
/// ```no_run
/// # fn demo(link: &skakel_client::Link) {
/// link.set_pin_store(|pins: skakel_client::Pins| async move {
///     std::fs::write("pins.txt", pins.fingerprint())?;
///     Ok::<(), std::io::Error>(())
/// });
/// # }
/// ```
pub trait PinStore: Send + Sync + 'static {
    /// Saves the pins.
    fn save(&self, pins: Pins) -> SaveFuture;
}

impl<F, Fut, E> PinStore for F
where
    F: Fn(Pins) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), E>> + Send + 'static,
    E: Into<StoreError>,
{
    fn save(&self, pins: Pins) -> SaveFuture {
        let saving = self(pins);
        Box::pin(async move { saving.await.map_err(Into::into) })
    }
}

/// Something that happened to a link, in order. See [`Link::events`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinkEvent {
    /// The link's state or failure changed. Renewing the control call before its token runs out is
    /// not a change. An app whose own services push state calls them again when the link is
    /// [`LinkState::Connected`] after it was not, since the calls of a lost connection are over.
    Status(LinkStatus),
    /// The link followed its server to another address on the local network. Save the address.
    AddressChanged(Url),
    /// The server's word about its certificates changed the pins: a next one to trust as well, a
    /// switch to it, or a cancelled one. The [`PinStore`] has them too.
    PinsChanged(Pins),
}

/// How many events a slow subscriber may fall behind.
const EVENT_BACKLOG: usize = 64;

/// Where a link stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    /// Not started, or stopped.
    Stopped,
    /// Connecting, the first time or again after a failure.
    Connecting,
    /// The control channel is up. Renewing its call before the token runs out does not leave this
    /// state.
    Connected,
    /// The last attempt failed, or the connection was lost; the link tries again after a pause.
    Failed,
    /// The server ended the client for good: revoked it, rotated its secret, or refused its
    /// credentials. The link does not try again; the client has to pair again.
    Closed,
}

/// Where a link stands, and why when it is not connected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkStatus {
    /// The state.
    pub state: LinkState,
    /// What went wrong, in [`LinkState::Failed`] and [`LinkState::Closed`].
    pub failure: Option<Failure>,
}

impl LinkStatus {
    fn of(state: LinkState) -> Self {
        Self {
            state,
            failure: None,
        }
    }

    fn with(state: LinkState, failure: Failure) -> Self {
        Self {
            state,
            failure: Some(failure),
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

struct Running {
    stop: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

#[derive(Default)]
struct Following {
    stranded: bool,
    running: bool,
    again: bool,
    task: Option<tokio::task::JoinHandle<()>>,
    browser_watch: Option<tokio::task::JoinHandle<()>>,
}

struct Inner {
    options: ClientOptions,
    clock: Arc<dyn Clock>,
    address: Arc<Mutex<Url>>,
    pins: Arc<Mutex<Pins>>,
    /// The pins the app's handlers last accepted, which the app has saved. `pins` follows what the
    /// server says at once, so connections work, and `saved_pins` is what tells that apart.
    saved_pins: Mutex<Pins>,
    credentials: Credentials,
    http: HttpClient,
    tokens: TokenClient,
    moves: ServerMoves,
    browser: Option<Browser>,
    _protection: Option<Protection>,
    status: watch::Sender<LinkStatus>,
    /// The control channel's connection while it is up, for the app's own calls.
    control: watch::Sender<Option<Connection>>,
    /// When the last connection or `Connect` call started.
    last_start: Mutex<Option<Instant>>,
    wake: Notify,
    run: Mutex<Option<Running>>,
    following: Mutex<Following>,
    events: broadcast::Sender<LinkEvent>,
    address_watch: watch::Sender<Url>,
    pins_watch: watch::Sender<Pins>,
    pin_store: Mutex<Option<Arc<dyn PinStore>>>,
}

impl Inner {
    fn pins_fn(&self) -> http::PinsFn {
        let pins = self.pins.clone();
        Arc::new(move || lock(&pins).clone())
    }
}

/// A client's link to one server.
pub struct Link {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Link")
            .field("address", &self.address().as_str())
            .field("status", &self.status().state)
            .finish_non_exhaustive()
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        if let Some(run) = lock(&self.inner.run).take() {
            run.stop.cancel();
        }
        let mut following = lock(&self.inner.following);
        for task in [following.task.take(), following.browser_watch.take()]
            .into_iter()
            .flatten()
        {
            task.abort();
        }
    }
}

impl Link {
    /// A link to a server. Call [`start`](Self::start) to bring the control channel up; the
    /// streams, hello and HTTPS requests work without it.
    ///
    /// `address` is the server's HTTPS address, `pins` its certificates and `credentials` the
    /// client's credentials on that server, all as the app saved them.
    pub fn new(
        address: &Url,
        pins: Pins,
        credentials: Credentials,
        options: ClientOptions,
    ) -> Result<Self> {
        let address = http::base_address(address)?;
        let initial_address = address.clone();
        let address = Arc::new(Mutex::new(address));
        let saved_pins = Mutex::new(pins.clone());
        let initial_pins = pins.clone();
        let pins = Arc::new(Mutex::new(pins));
        let pins_fn: http::PinsFn = {
            let pins = pins.clone();
            Arc::new(move || lock(&pins).clone())
        };
        let http = HttpClient::new(pins_fn.clone(), None);
        let clock = options.clock.clone();
        let tokens = TokenClient::new(
            http.clone(),
            {
                let address = address.clone();
                move || lock(&address).clone()
            },
            credentials.clone(),
            clock.clone(),
            options.request_timeout,
        );
        let browser = options.browser.clone();
        let protection = browser.as_ref().map(|b| b.protect(pins_fn));
        Ok(Self {
            inner: Arc::new(Inner {
                moves: ServerMoves::new(clock.clone()),
                clock,
                address,
                pins,
                saved_pins,
                credentials,
                http,
                tokens,
                browser,
                _protection: protection,
                status: watch::channel(LinkStatus::of(LinkState::Stopped)).0,
                control: watch::channel(None).0,
                last_start: Mutex::new(None),
                wake: Notify::new(),
                run: Mutex::new(None),
                following: Mutex::new(Following::default()),
                events: broadcast::channel(EVENT_BACKLOG).0,
                address_watch: watch::channel(initial_address).0,
                pins_watch: watch::channel(initial_pins).0,
                pin_store: Mutex::new(None),
                options,
            }),
        })
    }

    /// The server's address. It changes when the link follows the server to another one.
    pub fn address(&self) -> Url {
        lock(&self.inner.address).clone()
    }

    /// The certificates the link trusts now.
    pub fn pins(&self) -> Pins {
        lock(&self.inner.pins).clone()
    }

    /// The credentials the link signs in with.
    pub fn credentials(&self) -> &Credentials {
        &self.inner.credentials
    }

    /// Where the link stands.
    pub fn status(&self) -> LinkStatus {
        self.inner.status.borrow().clone()
    }

    /// The status, to read now and to wait on for changes. A watcher sees the latest status, not
    /// every one in between; [`events`](Self::events) has them all.
    pub fn watch_status(&self) -> StateWatch<LinkStatus> {
        StateWatch::new(self.inner.status.subscribe())
    }

    /// The server's address, to read now and to wait on. It changes when the link follows the
    /// server to another one.
    pub fn watch_address(&self) -> StateWatch<Url> {
        StateWatch::new(self.inner.address_watch.subscribe())
    }

    /// The pins, to read now and to wait on. They change on a certificate handover.
    pub fn watch_pins(&self) -> StateWatch<Pins> {
        StateWatch::new(self.inner.pins_watch.subscribe())
    }

    /// What happens to the link from now on, in order: each change of status, a move to another
    /// address and a change of pins. A subscriber that is not read for long misses the oldest events
    /// and is told; the link never waits for one.
    pub fn events(&self) -> Events<LinkEvent> {
        Events::new(self.inner.events.subscribe())
    }

    /// Where the pins are kept. The link hands every change of its pins to the store, and tells the
    /// server it has the next certificate only once the store has saved them. Without a store the
    /// pins live as long as the link, and the app saves what [`watch_pins`](Self::watch_pins) gives.
    /// Replaces the store set before.
    pub fn set_pin_store(&self, store: impl PinStore) {
        *lock(&self.inner.pin_store) = Some(Arc::new(store));
    }

    /// Starts keeping the control channel up, in the background. Watch it with [`events`](Self::events) and [`watch_status`](Self::watch_status).
    /// Starting a started link does nothing.
    pub fn start(&self) {
        let mut run = lock(&self.inner.run);
        // A link that closed for good has no task left, so it starts again; one that is still
        // running, in any state, does not start twice.
        if run
            .as_ref()
            .is_some_and(|running| !running.task.is_finished())
        {
            return;
        }
        let stop = CancellationToken::new();
        let task = tokio::spawn(run_loop(self.inner.clone(), stop.clone()));
        *run = Some(Running { stop, task });
        drop(run);
        if let Some(browser) = &self.inner.browser {
            let mut changes = browser.watch();
            let inner = self.inner.clone();
            let watching = tokio::spawn(async move {
                while changes.changed().await.is_ok() {
                    request_follow(&inner);
                }
            });
            if let Some(previous) = lock(&self.inner.following).browser_watch.replace(watching) {
                previous.abort();
            }
        }
    }

    /// Closes the control channel and stops trying. Streams already open carry on.
    pub async fn stop(&self) {
        let Some(run) = lock(&self.inner.run).take() else {
            return;
        };
        run.stop.cancel();
        let _ = run.task.await;
        let (following, watching) = {
            let mut following = lock(&self.inner.following);
            (following.task.take(), following.browser_watch.take())
        };
        if let Some(watching) = watching {
            watching.abort();
        }
        if let Some(following) = following {
            let _ = following.await;
        }
        lock(&self.inner.following).running = false;
        set_status(&self.inner, LinkStatus::of(LinkState::Stopped)).await;
    }

    /// Checks the version and the credentials with `ControlService.Hello`, as an app's Test button
    /// does, on a connection of its own. Works whether the link is started or not.
    pub async fn hello(&self) -> Result<SkakelHello> {
        let address = self.address();
        let timeout = self.inner.options.request_timeout;
        let result = async {
            let info = read_info_with(&self.inner.http, &address, timeout).await?;
            require_version(&info.versions)?;
            let token = self.inner.tokens.get().await?;
            let connection = Connection::open(&address, self.inner.pins_fn(), timeout).await?;
            let mut control = ControlServiceClient::new(connection.service())
                .max_decoding_message_size(CONTROL_MESSAGE_LIMIT);
            let answer = tokio::time::timeout(
                timeout,
                control.hello(with_token(HelloRequest {}, &token.value)),
            )
            .await
            .map_err(Error::from_cause)?;
            let hello = match answer {
                Ok(answer) => answer.into_inner(),
                Err(status) => {
                    if is_token_refused(&status) {
                        self.inner.tokens.forget(&token.value).await;
                    }
                    return Err(call_failed(status));
                }
            };
            if hello.server.is_empty() || hello.client_id.is_empty() {
                return Err(bad_answer(
                    "The hello answer is missing the server or the client.",
                ));
            }
            Ok(SkakelHello {
                server: hello.server,
                client_id: hello.client_id,
            })
        }
        .await;
        if let Err(error) = &result {
            log::info!("hello on {} failed: {error:?}", http::authority(&address));
        }
        result
    }

    /// A token for this server, reused until shortly before it runs out. For a call the link does
    /// not make itself.
    pub async fn access_token(&self) -> Result<String> {
        match self.inner.tokens.get().await {
            Ok(token) => Ok(token.value),
            Err(error) => {
                log::info!(
                    "token on {} failed: {error:?}",
                    http::authority(&self.address())
                );
                Err(error)
            }
        }
    }

    /// Sends a request to one of the app's own HTTPS endpoints on this server: pinned, with the
    /// link's token on it, and the server's address as its base. `path` is the path and query,
    /// starting with `/`, so the token cannot leave for another host. `configure` adds the body
    /// and headers. A 401 drops the token, so the next call gets a new one.
    ///
    /// # Errors
    ///
    /// [`FailureKind::InvalidRequest`] when `path` does not start with a single `/`, has a
    /// backslash or a control character, or would land on another host.
    pub async fn request(
        &self,
        method: Method,
        path: &str,
        configure: impl FnOnce(RequestBuilder) -> RequestBuilder,
    ) -> Result<Response> {
        if !is_server_path(path) {
            log::warn!("A request to {path:?} was refused: not a path on the server");
            return Err(Error::of(FailureKind::InvalidRequest));
        }
        let address = self.address();
        let url = address.join(path).map_err(Error::from_cause)?;
        if !is_at(&url, &address) {
            log::warn!("A request to {path:?} was refused: it would leave the server");
            return Err(Error::of(FailureKind::InvalidRequest));
        }
        let result = async {
            let token = self.inner.tokens.get().await?;
            let builder = configure(RequestBuilder::for_link(method, url))
                .with_client(&self.inner.http)
                .timeout(self.inner.options.request_timeout)
                .max_response(MAX_APP_RESPONSE_BYTES)
                .bearer(&token.value);
            let response = builder.send().await?;
            if response.status() == StatusCode::UNAUTHORIZED {
                self.inner.tokens.forget(&token.value).await;
            }
            Ok(response)
        }
        .await;
        if let Err(error) = &result {
            log::info!("{path} on {} failed: {error:?}", http::authority(&address));
        }
        result
    }

    /// A channel for the app's own gRPC services on this server, for tonic's generated clients:
    /// `MyServiceClient::new(link.channel())`. Each call goes over the control channel's
    /// connection, pinned, with the link's newest token in its `authorization` metadata, so it
    /// needs the link started and connected. While it is not, a call fails with `UNAVAILABLE`.
    /// A call the server refuses with `TOKEN_REFUSED` drops the token, so the next call gets a new
    /// one.
    pub fn channel(&self) -> LinkChannel {
        LinkChannel {
            inner: self.inner.clone(),
        }
    }

    /// Opens a stream of `stream_type` on a connection of its own, pinned, with the link's token.
    /// `target` says what the stream is for, a message the type defines, encoded; empty for a type
    /// that needs nothing. A refusal before `opened` comes back in the result, with the server's
    /// reason and its words for it.
    ///
    /// # Errors
    ///
    /// [`FailureKind::InvalidRequest`] when `stream_type` is not one or more of `a-z`, `0-9` and
    /// `-`.
    pub async fn open_stream(
        &self,
        stream_type: &str,
        target: &[u8],
    ) -> Result<OpenResult<StreamConnection>> {
        if !is_stream_type(stream_type) {
            return Err(Error::of(FailureKind::InvalidRequest));
        }
        let address = self.address();
        let timeout = self.inner.options.request_timeout;
        let result = async {
            let mut attempt = 1;
            loop {
                let token = self.inner.tokens.get().await?;
                let connection = Connection::open(&address, self.inner.pins_fn(), timeout).await?;
                let result =
                    streams::open(connection, stream_type, target, &token.value, timeout).await?;
                if let OpenResult::Refused(refusal) = &result {
                    if refusal.reason == StreamRefusalReason::Unauthorized && attempt == 1 {
                        // The token may have just run out on the server's clock; one more try
                        // with a fresh one.
                        self.inner.tokens.forget(&token.value).await;
                        attempt += 1;
                        continue;
                    }
                    log::info!(
                        "{} refused a {stream_type} stream with {:?}: {}",
                        http::authority(&address),
                        refusal.reason,
                        refusal.message
                    );
                }
                return Ok(result);
            }
        }
        .await;
        if let Err(error) = &result {
            log::info!(
                "{stream_type} on {} failed: {error:?}",
                http::authority(&address)
            );
        }
        result
    }

    /// Opens a `serial` stream to the port with this id in the app's list of ports, and waits for
    /// the server to say the port is open. A second client gets a refusal with
    /// [`StreamRefusalReason::InUse`].
    ///
    /// # Errors
    ///
    /// [`FailureKind::InvalidRequest`] when `port_id` is empty.
    pub async fn open_serial(&self, port_id: &str) -> Result<OpenResult<SerialConnection>> {
        if port_id.is_empty() {
            return Err(Error::of(FailureKind::InvalidRequest));
        }
        match self
            .open_stream(STREAM_TYPE, &skakel_serial::target(port_id))
            .await?
        {
            OpenResult::Refused(refusal) => Ok(OpenResult::Refused(refusal)),
            OpenResult::Opened(stream) => match SerialConnection::start(stream).await {
                Ok(serial) => Ok(OpenResult::Opened(serial)),
                Err(error) => {
                    log::info!(
                        "serial on {} failed: {error:?}",
                        http::authority(&self.address())
                    );
                    Err(error)
                }
            },
        }
    }

    /// The search for a server that moved, while one runs; for a test to wait on.
    #[doc(hidden)]
    pub async fn following(&self) {
        loop {
            let task = {
                let mut following = lock(&self.inner.following);
                if !following.running {
                    return;
                }
                following.task.take()
            };
            match task {
                Some(task) => {
                    let _ = task.await;
                }
                None => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    }
}

/// The app's own gRPC calls over a link's control connection, for tonic's generated clients. See
/// [`Link::channel`]. Cloning it is cheap; every clone follows the link's current connection.
#[derive(Clone)]
pub struct LinkChannel {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for LinkChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkChannel").finish_non_exhaustive()
    }
}

impl tower_service::Service<tonic::codegen::http::Request<Body>> for LinkChannel {
    type Response = tonic::codegen::http::Response<Body>;
    type Error = Status;
    type Future = grpc::BoxFuture<std::result::Result<Self::Response, Status>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::result::Result<(), Status>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut request: tonic::codegen::http::Request<Body>) -> Self::Future {
        let inner = self.inner.clone();
        Box::pin(async move {
            let connection = inner.control.borrow().clone();
            let Some(connection) = connection.filter(|c| !c.is_closed()) else {
                return Err(Status::unavailable(
                    Failure::of(FailureKind::NotConnected).message(),
                ));
            };
            let token = inner.tokens.get().await.map_err(|error| {
                let message = error.failure().message().to_owned();
                if matches!(
                    error.kind(),
                    FailureKind::Unreachable | FailureKind::ConnectionLost
                ) {
                    Status::unavailable(message)
                } else {
                    Status::unauthenticated(message)
                }
            })?;
            let mut value: tonic::codegen::http::HeaderValue = format!("Bearer {}", token.value)
                .parse()
                .map_err(|_| Status::internal("The token is not a header value."))?;
            value.set_sensitive(true);
            request.headers_mut().insert("authorization", value);
            let mut service = connection.service();
            std::future::poll_fn(|cx| tower_service::Service::poll_ready(&mut service, cx)).await?;
            let response = tower_service::Service::call(&mut service, request).await?;
            // A refusal comes as the whole answer, before any message.
            if Status::from_header_map(response.headers()).is_some_and(|s| is_token_refused(&s)) {
                inner.tokens.forget(&token.value).await;
            }
            Ok(response)
        })
    }
}

/// Whether `path` is a path and query on a server: one `/` first, no backslash, no control
/// character or space that a URL parser would drop or turn into something else.
fn is_server_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("//")
        && !path
            .chars()
            .any(|c| c == '\\' || c.is_control() || c == ' ')
}

/// Hands the pins to the app's store. True when it saved them, or when there is no store. The store
/// runs on a task of its own, so one that panics cannot take the link down with it.
async fn save_pins(inner: &Inner, pins: Pins) -> bool {
    let store = lock(&inner.pin_store).clone();
    let Some(store) = store else {
        return true;
    };
    let saving = tokio::spawn(async move { store.save(pins).await });
    match saving.await {
        Ok(Ok(())) => true,
        Ok(Err(error)) => {
            log::warn!("The pin store failed to save the pins: {error}");
            false
        }
        Err(error) => {
            log::warn!("The pin store panicked while saving the pins: {error}");
            false
        }
    }
}

/// Sets the status and tells subscribers when it changed.
async fn set_status(inner: &Inner, status: LinkStatus) {
    let changed = inner.status.send_if_modified(|current| {
        if *current == status {
            false
        } else {
            *current = status.clone();
            true
        }
    });
    if changed {
        let _ = inner.events.send(LinkEvent::Status(status));
    }
}

/// Keeps the control channel up until stopped. Catches everything: a link fails visibly, never
/// silently.
async fn run_loop(inner: Arc<Inner>, stop: CancellationToken) {
    let mut backoff = MIN_BACKOFF;
    while !stop.is_cancelled() {
        let address = lock(&inner.address).clone();
        let started = inner.clock.instant();
        match connect_once(&inner, &address, &stop).await {
            Ok(None) => return,
            Ok(Some(end)) => {
                if ends_for_good(end.kind()) {
                    log::warn!(
                        "{} ended this client: {}. The link stops",
                        http::authority(&address),
                        end.code()
                    );
                    set_status(&inner, LinkStatus::with(LinkState::Closed, end)).await;
                    return;
                }
                // It was up; whatever ended it, the next try comes soon.
                log::warn!(
                    "The link to {} was lost: {}",
                    http::authority(&address),
                    end.code()
                );
                set_status(&inner, LinkStatus::with(LinkState::Failed, end)).await;
                if since(inner.clock.instant(), started) >= STABLE_AFTER {
                    backoff = MIN_BACKOFF;
                }
            }
            Err(error) => {
                if stop.is_cancelled() {
                    return;
                }
                if ends_for_good(error.kind()) {
                    log::warn!(
                        "{} refused this client: {}: {error:?}. The link stops",
                        http::authority(&address),
                        error.failure().code()
                    );
                    set_status(
                        &inner,
                        LinkStatus::with(LinkState::Closed, error.failure().clone()),
                    )
                    .await;
                    return;
                }
                log::warn!(
                    "The link to {} failed: {}: {error:?}",
                    http::authority(&address),
                    error.failure().code()
                );
                set_status(
                    &inner,
                    LinkStatus::with(LinkState::Failed, error.failure().clone()),
                )
                .await;
                if is_unreachable(&error) && inner.browser.is_some() {
                    lock(&inner.following).stranded = true;
                    request_follow(&inner);
                }
            }
        }

        pause(&inner, jittered(backoff), &stop).await;
        if stop.is_cancelled() {
            return;
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// True for a failure that trying again cannot mend: the server revoked the client, rotated its
/// secret, or its token endpoint refused the credentials. The client has to pair again.
fn ends_for_good(kind: FailureKind) -> bool {
    matches!(
        kind,
        FailureKind::Revoked | FailureKind::Rotated | FailureKind::RejectedCredentials
    )
}

/// A pause of between half of `delay` and all of it, so links to one server that restarted do not
/// all come back in the same instant.
fn jittered(delay: Duration) -> Duration {
    let mut byte = [0u8; 1];
    if getrandom::fill(&mut byte).is_err() {
        return delay;
    }
    delay.mul_f64(0.5 + f64::from(byte[0]) / 510.0)
}

/// Waits before the next try. A move ends the wait at once.
async fn pause(inner: &Inner, delay: Duration, stop: &CancellationToken) {
    tokio::select! {
        () = inner.clock.sleep(delay) => {}
        () = inner.wake.notified() => {}
        () = stop.cancelled() => {}
    }
}

/// Waits until a second has passed since the last connection or `Connect` call started, then notes
/// this one. False when the link was stopped meanwhile.
async fn pace(inner: &Inner, stop: &CancellationToken) -> bool {
    let last = *lock(&inner.last_start);
    if let Some(last) = last {
        let gone = since(inner.clock.instant(), last);
        if gone < MIN_BACKOFF {
            tokio::select! {
                () = inner.clock.sleep(MIN_BACKOFF - gone) => {}
                () = stop.cancelled() => return false,
            }
        }
    }
    *lock(&inner.last_start) = Some(inner.clock.instant());
    !stop.is_cancelled()
}

/// One control call: what the client sends on it, and what the server answers.
struct ControlCall {
    requests: mpsc::Sender<ConnectRequest>,
    answers: Streaming<ConnectResponse>,
}

/// Calls `Connect` on `connection` with `token` and waits up to `timeout` for the server's
/// `certificates`. An error status (a refusal) comes back as `Err(Ok(status))`; anything else that
/// went wrong as `Err(Err(error))`.
async fn open_call(
    connection: &Connection,
    token: &str,
    timeout: Duration,
) -> std::result::Result<(ControlCall, Certificates), std::result::Result<Status, Error>> {
    let (requests, rx) = mpsc::channel(CONTROL_QUEUE);
    let mut control = ControlServiceClient::new(connection.service())
        .max_decoding_message_size(CONTROL_MESSAGE_LIMIT)
        .max_encoding_message_size(CONTROL_MESSAGE_LIMIT);
    let opening = async {
        let mut answers = control
            .connect(with_token(ReceiverStream::new(rx), token))
            .await?
            .into_inner();
        loop {
            match answers.message().await? {
                Some(ConnectResponse {
                    message: Some(connect_response::Message::Certificates(certificates)),
                }) => return Ok(Some((answers, certificates))),
                // A kind this end does not know.
                Some(ConnectResponse { message: None }) => {}
                Some(_) | None => return Ok(None),
            }
        }
    };
    match tokio::time::timeout(timeout, opening).await {
        Err(elapsed) => Err(Err(Error::caused(FailureKind::UnexpectedAnswer, elapsed))),
        Ok(Err(status)) => Err(Ok(status)),
        Ok(Ok(None)) => Err(Err(bad_answer(
            "The control call did not start with the certificates.",
        ))),
        Ok(Ok(Some((answers, certificates)))) => {
            Ok((ControlCall { requests, answers }, certificates))
        }
    }
}

/// When to renew a control call opened with `token`: half a minute ahead of its end; a token with
/// less than a minute left is renewed halfway through what it has.
fn renew_at(inner: &Inner, token: &Token) -> Instant {
    let left = since(token.expires_at, inner.clock.instant());
    token.expires_at - REFRESH_AHEAD.min(left / 2)
}

/// How a control connection ended.
enum End {
    Stopped,
    Failure(Failure),
}

/// One control connection, from start to end. `None` when the link was stopped; otherwise why the
/// connection ended. An error when it could not connect.
async fn connect_once(
    inner: &Arc<Inner>,
    address: &Url,
    stop: &CancellationToken,
) -> Result<Option<Failure>> {
    let timeout = inner.options.request_timeout;
    set_status(inner, LinkStatus::of(LinkState::Connecting)).await;
    let info = tokio::select! {
        () = stop.cancelled() => return Ok(None),
        info = read_info_with(&inner.http, address, timeout) => info?,
    };
    require_version(&info.versions)?;
    let mut token = tokio::select! {
        () = stop.cancelled() => return Ok(None),
        token = inner.tokens.get() => token?,
    };
    if !pace(inner, stop).await {
        return Ok(None);
    }
    let connection = tokio::select! {
        () = stop.cancelled() => return Ok(None),
        connection = Connection::open(address, inner.pins_fn(), timeout) => connection?,
    };

    // A refused token gets one more try with a fresh one.
    let mut tries = 0;
    let (mut call, certificates) = loop {
        tries += 1;
        let opened = tokio::select! {
            () = stop.cancelled() => return Ok(None),
            opened = open_call(&connection, &token.value, timeout) => opened,
        };
        match opened {
            Ok(opened) => break opened,
            Err(Ok(status)) if is_token_refused(&status) && tries == 1 => {
                inner.tokens.forget(&token.value).await;
                token = tokio::select! {
                    () = stop.cancelled() => return Ok(None),
                    token = inner.tokens.get() => token?,
                };
                if !pace(inner, stop).await {
                    return Ok(None);
                }
            }
            Err(Ok(status)) => {
                if is_token_refused(&status) {
                    inner.tokens.forget(&token.value).await;
                }
                return Err(call_failed(status));
            }
            Err(Err(error)) => return Err(error),
        }
    };

    learn_certificates(inner, &connection, &call.requests, address, certificates).await;
    inner.control.send_replace(Some(connection.clone()));
    lock(&inner.following).stranded = false;
    log::info!("Connected to {}", http::authority(address));
    set_status(inner, LinkStatus::of(LinkState::Connected)).await;

    let end = serve(inner, &connection, &mut call, &mut token, address, stop).await;

    // Whatever ended it, this connection is over: nobody's calls go through it any more.
    inner.control.send_if_modified(|current| {
        if current.is_some() {
            *current = None;
            true
        } else {
            false
        }
    });
    Ok(match end {
        End::Stopped => None,
        End::Failure(failure) => Some(failure),
    })
}

/// What a closing reason or an ending status means for the link.
fn failure_of(reason: Reason) -> Option<Failure> {
    match reason {
        Reason::Revoked => Some(Failure::of(FailureKind::Revoked)),
        Reason::Rotated => Some(Failure::of(FailureKind::Rotated)),
        Reason::Stopping => Some(Failure::of(FailureKind::ServerStopping)),
        _ => None,
    }
}

/// Runs a control connection: reads what the server says, renews the call before its token runs
/// out, and says why it ended.
async fn serve(
    inner: &Arc<Inner>,
    connection: &Connection,
    call: &mut ControlCall,
    token: &mut Token,
    address: &Url,
    stop: &CancellationToken,
) -> End {
    let timeout = inner.options.request_timeout;
    let mut closing: Option<Reason> = None;
    loop {
        let wait = since(renew_at(inner, token), inner.clock.instant()).min(ACCESS_TOKEN_LIFETIME);
        let renew = tokio::select! {
            () = stop.cancelled() => return End::Stopped,
            () = connection.closed() => {
                return End::Failure(closing.and_then(failure_of).unwrap_or_else(|| Failure::of(FailureKind::ConnectionLost)));
            }
            () = inner.clock.sleep(wait) => true,
            answer = call.answers.message() => match answer {
                Ok(Some(ConnectResponse { message: Some(connect_response::Message::Certificates(certificates)) })) => {
                    learn_certificates(inner, connection, &call.requests, address, certificates).await;
                    false
                }
                Ok(Some(ConnectResponse { message: Some(connect_response::Message::Closing(said)) })) => {
                    let reason = match ClosingReason::try_from(said.reason) {
                        Ok(ClosingReason::Revoked) => Reason::Revoked,
                        Ok(ClosingReason::Rotated) => Reason::Rotated,
                        // A reason this end does not know counts as stopping.
                        _ => Reason::Stopping,
                    };
                    log::info!("{} is closing the control call: {reason}", http::authority(address));
                    closing = Some(reason);
                    false
                }
                // A kind this end does not know.
                Ok(Some(_)) => false,
                Ok(None) => {
                    log::info!("{} ended the control call without a reason", http::authority(address));
                    return End::Failure(Failure::of(FailureKind::ConnectionLost));
                }
                Err(status) => match reason_of(&status) {
                    // The renewal was late, or the server's clock is ahead: renew now, with a token
                    // that is not the one that ran out.
                    Some(Reason::TokenExpired) => {
                        inner.tokens.forget(&token.value).await;
                        true
                    }
                    Some(reason) if failure_of(reason).is_some() => {
                        return End::Failure(failure_of(reason).expect("checked"));
                    }
                    Some(Reason::TokenRefused) => {
                        inner.tokens.forget(&token.value).await;
                        return End::Failure(Failure::of(FailureKind::ClientUnknown));
                    }
                    _ => {
                        log::info!(
                            "The control call to {} ended: {:?} {}",
                            http::authority(address),
                            status.code(),
                            status.message()
                        );
                        return End::Failure(
                            closing
                                .and_then(failure_of)
                                .unwrap_or_else(|| Failure::of(FailureKind::ConnectionLost)),
                        );
                    }
                },
            },
        };
        if !renew {
            continue;
        }

        // Renewing: a fresh token, a new call on the same connection, and the old one let go once
        // the new one has said the certificates. A refused token gets one more try with another.
        let mut tries = 0;
        let (renewed, certificates, fresh) = loop {
            tries += 1;
            let fresh = tokio::select! {
                () = stop.cancelled() => return End::Stopped,
                fresh = inner.tokens.get() => fresh,
            };
            let fresh = match fresh {
                Ok(fresh) => fresh,
                Err(error) => return End::Failure(error.failure().clone()),
            };
            if !pace(inner, stop).await {
                return End::Stopped;
            }
            let opened = tokio::select! {
                () = stop.cancelled() => return End::Stopped,
                opened = open_call(connection, &fresh.value, timeout) => opened,
            };
            match opened {
                Ok((renewed, certificates)) => break (renewed, certificates, fresh),
                Err(Ok(status)) if is_token_refused(&status) => {
                    inner.tokens.forget(&fresh.value).await;
                    if tries > 1 {
                        return End::Failure(Failure::of(FailureKind::ClientUnknown));
                    }
                }
                Err(Ok(status)) => {
                    return End::Failure(
                        reason_of(&status)
                            .and_then(failure_of)
                            .unwrap_or_else(|| Failure::of(FailureKind::ConnectionLost)),
                    );
                }
                Err(Err(error)) => {
                    log::info!(
                        "Renewing the control call to {} failed: {error:?}",
                        http::authority(address)
                    );
                    return End::Failure(Failure::of(FailureKind::ConnectionLost));
                }
            }
        };
        *call = renewed;
        *token = fresh;
        log::debug!("Renewed the control call to {}", http::authority(address));
        learn_certificates(inner, connection, &call.requests, address, certificates).await;
    }
}

/// The server told the link which certificate it presents and which one it will switch to. The link
/// is pinned to a certificate it trusts, so it may vouch for the next one: it is trusted as well, or
/// becomes the pinned one once the server presents it. Once the app saved the pins, the server is
/// told the client has the next one. A fingerprint that is not one is ignored. So is a statement
/// about a certificate this connection did not present, unless a new connection to the server
/// presents it, as after a switch, when the control connection still runs on the old certificate.
async fn learn_certificates(
    inner: &Arc<Inner>,
    connection: &Connection,
    requests: &mpsc::Sender<ConnectRequest>,
    address: &Url,
    certificates: Certificates,
) {
    let next = Some(certificates.next_fingerprint.as_str()).filter(|n| !n.is_empty());
    if fingerprints::normalize(&certificates.fingerprint).is_none()
        || next.is_some_and(|next| fingerprints::normalize(next).is_none())
    {
        log::warn!("The server sent certificates that are not fingerprints; ignored");
        return;
    }

    let on_this_connection = connection
        .presented()
        .is_some_and(|p| fingerprints::are_equal(&certificates.fingerprint, p));
    if !on_this_connection && !presents(inner, address, &certificates.fingerprint).await {
        log::warn!(
            "The server spoke of its certificate {}, which it does not present; ignored",
            certificates.fingerprint
        );
        return;
    }

    let after = {
        let mut pins = lock(&inner.pins);
        let after = pins.with_server_certificates(&certificates.fingerprint, next);
        *pins = after.clone();
        after
    };
    // Compared with what the app saved, not with what the link held a moment ago: a handover the
    // app failed to save is offered to it again on the next connection, and is acknowledged only
    // once the app has it.
    let unsaved = *lock(&inner.saved_pins) != after;
    if unsaved {
        log::info!(
            "The server's certificates changed: pinned {}, next {}",
            after.fingerprint(),
            after.next_fingerprint().unwrap_or("none")
        );
        inner.pins_watch.send_replace(after.clone());
        let _ = inner.events.send(LinkEvent::PinsChanged(after.clone()));
        if !save_pins(inner, after.clone()).await {
            // Not saved: the server is not told, and says it again on the next connection.
            return;
        }
        *lock(&inner.saved_pins) = after.clone();
    }

    if let (Some(stored), Some(said)) = (after.next_fingerprint(), next)
        && fingerprints::are_equal(stored, said)
    {
        let received = ConnectRequest {
            message: Some(connect_request::Message::NextCertificateReceived(
                NextCertificateReceived {
                    fingerprint: stored.to_owned(),
                },
            )),
        };
        if requests.send(received).await.is_err() {
            log::info!(
                "Telling {} the next certificate was stored failed: the call is over",
                http::authority(address)
            );
        }
    }
}

/// Whether a new connection to `address`, pinned as the link is, presents the certificate
/// `fingerprint`. Within five seconds, as a move's proof.
async fn presents(inner: &Inner, address: &Url, fingerprint: &str) -> bool {
    let presented = http::presented();
    let client = HttpClient::new(inner.pins_fn(), Some(presented.clone()));
    match get_info(&client, address).await {
        Ok(()) => http::last_presented(&presented)
            .is_some_and(|p| fingerprints::are_equal(&p, fingerprint)),
        Err(error) => {
            log::info!(
                "certificate check on {} failed: {error}",
                http::authority(address)
            );
            false
        }
    }
}

/// `GET /skakel/info` on `server` over `client`, within the proof time. Any answer after the
/// handshake the client pins is the proof; a handshake that fails or takes too long is not.
async fn get_info(client: &HttpClient, server: &Url) -> std::result::Result<(), String> {
    let url = server.join(INFO_PATH).map_err(|e| e.to_string())?;
    client
        .get(url)
        .timeout(PROOF_TIMEOUT)
        .send()
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Starts a search for the server in the background, while the link cannot reach it. A request
/// while one runs has it look once more when it is done, at the addresses heard by then, so
/// searches never pile up and a slow proof never holds up the browser's other listeners.
fn request_follow(inner: &Arc<Inner>) {
    if lock(&inner.run).is_none() {
        return;
    }
    let Some(browser) = inner.browser.clone() else {
        return;
    };
    let mut following = lock(&inner.following);
    if !following.stranded {
        return;
    }
    if following.running {
        following.again = true;
        return;
    }
    following.running = true;
    let inner = inner.clone();
    following.task = Some(tokio::spawn(async move {
        follow_while_asked(inner, browser).await
    }));
}

async fn follow_while_asked(inner: Arc<Inner>, browser: Browser) {
    loop {
        follow(&inner, &browser.entries()).await;
        let mut following = lock(&inner.following);
        let stopped = lock(&inner.run).is_none();
        if !following.again || !following.stranded || stopped {
            following.again = false;
            following.running = false;
            return;
        }
        following.again = false;
    }
}

/// Moves the link to where its server is now, if discovery heard it elsewhere and it proved it
/// holds the certificate.
async fn follow(inner: &Arc<Inner>, servers: &[crate::browser::DiscoveredServer]) {
    let from = lock(&inner.address).clone();
    let pins = lock(&inner.pins).clone();
    let to = inner
        .moves
        .find(&from, &pins, servers, |url| proves(inner, url))
        .await;
    let Some(to) = to else {
        return;
    };
    {
        let mut address = lock(&inner.address);
        if *address != from {
            return;
        }
        *address = to.clone();
        lock(&inner.following).stranded = false;
    }
    inner.wake.notify_one();
    log::info!(
        "The server stopped answering at {} and was found at {}; the link follows it",
        http::authority(&from),
        http::authority(&to)
    );
    inner.address_watch.send_replace(to.clone());
    let _ = inner.events.send(LinkEvent::AddressChanged(to));
}

/// Whether `url` holds a certificate the link trusts: `GET /skakel/info` over the pinned client,
/// with no token, within five seconds. Any answer after the pinned handshake proves it; a handshake
/// that fails or takes too long does not.
fn proves(inner: &Arc<Inner>, url: Url) -> impl Future<Output = bool> + use<> {
    let http = inner.http.clone();
    async move {
        match get_info(&http, &url).await {
            Ok(()) => true,
            Err(error) => {
                log::warn!(
                    "A server with the pinned fingerprint was heard at {}, but it did not prove it holds the certificate: {error}",
                    http::authority(&url)
                );
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pause_is_between_half_of_the_delay_and_all_of_it() {
        for _ in 0..200 {
            let pause = jittered(Duration::from_secs(8));
            assert!(
                pause >= Duration::from_secs(4) && pause <= Duration::from_secs(8),
                "{pause:?}"
            );
        }
    }

    #[test]
    fn link_states_compare_by_state_and_failure() {
        let a = LinkStatus::of(LinkState::Failed);
        let b = LinkStatus::with(LinkState::Failed, Failure::of(FailureKind::Unreachable));

        assert_ne!(a, b);
    }

    #[test]
    fn closing_reasons_are_failures_and_others_are_not() {
        assert_eq!(
            failure_of(Reason::Revoked).map(|f| f.kind()),
            Some(FailureKind::Revoked)
        );
        assert_eq!(
            failure_of(Reason::Rotated).map(|f| f.kind()),
            Some(FailureKind::Rotated)
        );
        assert_eq!(
            failure_of(Reason::Stopping).map(|f| f.kind()),
            Some(FailureKind::ServerStopping)
        );
        assert_eq!(failure_of(Reason::TokenExpired), None);
    }
}
