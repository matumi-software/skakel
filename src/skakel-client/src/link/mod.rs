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

mod certs;
mod channel;
mod control;
mod follow;
mod notify;

use self::certs::*;
pub use self::channel::LinkChannel;
use self::control::*;
use self::follow::*;
use self::notify::*;
pub use self::notify::{LinkEvent, PinStore, SaveFuture, StoreError};

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use ::http::{Method, StatusCode};
use skakel_proto::v3::control_service_client::ControlServiceClient;
use skakel_proto::v3::{
    Certificates, ConnectRequest, ConnectResponse, HelloRequest, NextCertificateReceived,
    connect_request, connect_response,
};
use skakel_serial::STREAM_TYPE;
use skakel_wire::{
    ACCESS_TOKEN_LIFETIME, CONTROL_MESSAGE_LIMIT, INFO_PATH, Reason, SkakelHello, fingerprints,
    is_stream_type,
};
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

/// Where a link stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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
#[non_exhaustive]
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
            Ok(hello.into())
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

    /// The search for a server that moved, while one runs; for a test to wait on. Behind the
    /// `test-util` feature.
    #[cfg(feature = "test-util")]
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

/// Whether `path` is a path and query on a server: one `/` first, no backslash, no control
/// character or space that a URL parser would drop or turn into something else.
fn is_server_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("//")
        && !path
            .chars()
            .any(|c| c == '\\' || c.is_control() || c == ' ')
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
