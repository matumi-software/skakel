//! A client's link to one server: HTTP pinned to the server's certificates, a token client, the
//! control hub, and the streams. An app holds one per server it is paired with.
//!
//! The app keeps the address, the pins and the credentials, and hands them in. What changes goes
//! back out as handlers: [`Link::on_pins_changed`] during a certificate handover,
//! [`Link::on_address_changed`] when the server moved on the local network. Save the new values in
//! the handler; a pins handler that returns an error is taken as not saved.
//!
//! Once started, the link keeps the hub connected: it reads `/skakel/info` to check the version,
//! connects with a token, connects again with a fresh token 30 seconds before the token runs out
//! without saying so, and after a failure tries again with a pause that grows to a minute. Two
//! connections never start less than a second apart, and a token is taken to last 2 to 30 minutes
//! whatever the server says. A revoke or rotation on the server ends it for good, as
//! [`LinkState::Closed`].

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use reqwest::{Method, StatusCode, Url};
use serde::de::DeserializeOwned;
use serde_json::Value;
use skakel_protocol::{
    ACCESS_TOKEN_LIFETIME, BASE_PATH, CLOSING_REVOKED, CLOSING_ROTATED, CLOSING_STOPPING,
    HELLO_PATH, HUB_CERTIFICATES, HUB_CLOSING, HUB_NEXT_CERTIFICATE_RECEIVED, HUB_PREFIX,
    INFO_PATH, SkakelCertificates, SkakelClosing, SkakelHello, fingerprints, is_stream_type,
};
use skakel_serial::{PORT_QUERY, STREAM_TYPE};
use tokio::sync::{Notify, oneshot, watch};
use tokio_util::sync::CancellationToken;

use crate::browser::{Browser, Protection};
use crate::clock::{Clock, since};
use crate::failure::{
    Error, Failure, FailureKind, Result, StatusError, bad_answer, is_unreachable,
};
use crate::http::{self, Presented, base_address, is_at};
use crate::hub::{HubConnection, HubEvent, InvokeError};
use crate::info::{read_info_with, require_version};
use crate::moves::{PROOF_TIMEOUT, ServerMoves};
use crate::options::ClientOptions;
use crate::pins::{Credentials, Pins};
use crate::serial::SerialConnection;
use crate::streams::{self, OpenResult, StreamConnection};
use crate::tokens::{Token, TokenClient};

/// How long before a token runs out the hub connects again with a fresh one.
const REFRESH_AHEAD: Duration = Duration::from_secs(30);

/// A close this close to the token's end is the server's expiry, not a failure.
const EXPIRY_GRACE: Duration = Duration::from_secs(10);

const MIN_BACKOFF: Duration = Duration::from_secs(1);

const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// What a handler may fail with.
pub type HandlerError = Box<dyn std::error::Error + Send + Sync>;

type HandlerFuture = Pin<Box<dyn Future<Output = Result<(), HandlerError>> + Send>>;
type Handler<T> = Arc<dyn Fn(T) -> HandlerFuture + Send + Sync>;

/// Where a link stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    /// Not started, or stopped.
    Stopped,
    /// Connecting, the first time or again after a failure.
    Connecting,
    /// The hub is connected. Renewing it before its token runs out does not leave this state.
    Connected,
    /// The last attempt failed, or the connection was lost; the link tries again after a pause.
    Failed,
    /// The server ended the client for good (revoked, or its secret rotated). The link does not try
    /// again.
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

/// Handles one of the app's own hub messages until dropped.
#[must_use = "dropping a subscription stops handling the message"]
pub struct Subscription {
    inner: std::sync::Weak<Inner>,
    id: u64,
}

impl Drop for Subscription {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.upgrade() {
            lock(&inner.messages).retain(|m| m.id != self.id);
        }
    }
}

struct MessageHandler {
    id: u64,
    method: String,
    handler: Handler<Vec<Value>>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// What one hub connection learned along the way, written by its callbacks.
struct Attempt {
    token: Mutex<Option<String>>,
    closing: Mutex<Option<String>>,
    /// The fingerprint of the certificate this connection's handshakes saw last.
    presented: Presented,
    refresh_at: Mutex<SystemTime>,
    expires_at: Mutex<SystemTime>,
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
    hub_path: String,
    address: Arc<Mutex<Url>>,
    pins: Arc<Mutex<Pins>>,
    credentials: Credentials,
    http: reqwest::Client,
    tokens: TokenClient,
    moves: ServerMoves,
    browser: Option<Browser>,
    _protection: Option<Protection>,
    status: watch::Sender<LinkStatus>,
    hub: watch::Sender<Option<Arc<HubConnection>>>,
    wake: Notify,
    run: Mutex<Option<Running>>,
    following: Mutex<Following>,
    status_handlers: Mutex<Vec<Handler<LinkStatus>>>,
    pins_handlers: Mutex<Vec<Handler<Pins>>>,
    address_handlers: Mutex<Vec<Handler<Url>>>,
    messages: Mutex<Vec<MessageHandler>>,
    next_message_id: AtomicU64,
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
    /// A link to a server. Call [`start`](Self::start) to connect the hub; the streams and requests
    /// work without it.
    ///
    /// `address` is the server's HTTPS address, `pins` its certificates and `credentials` the
    /// client's credentials on that server, all as the app saved them.
    ///
    /// # Panics
    ///
    /// When `options.hub_path` is not the app's own path under `/skakel/v1/`, such as `hub`.
    pub fn new(
        address: &Url,
        pins: Pins,
        credentials: Credentials,
        options: ClientOptions,
    ) -> Result<Self> {
        let address = Arc::new(Mutex::new(base_address(address)?));
        let hub_path = hub_path(&options.hub_path);
        let pins = Arc::new(Mutex::new(pins));
        let pins_fn: http::PinsFn = {
            let pins = pins.clone();
            Arc::new(move || lock(&pins).clone())
        };
        let http = http::client(pins_fn.clone(), None);
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
                hub_path,
                address,
                pins,
                credentials,
                http,
                tokens,
                browser,
                _protection: protection,
                status: watch::channel(LinkStatus::of(LinkState::Stopped)).0,
                hub: watch::channel(None).0,
                wake: Notify::new(),
                run: Mutex::new(None),
                following: Mutex::new(Following::default()),
                status_handlers: Mutex::new(Vec::new()),
                pins_handlers: Mutex::new(Vec::new()),
                address_handlers: Mutex::new(Vec::new()),
                messages: Mutex::new(Vec::new()),
                next_message_id: AtomicU64::new(1),
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

    /// The status as it changes, for a UI that shows the latest. A handler registered with
    /// [`on_status_changed`](Self::on_status_changed) hears every change, in order.
    pub fn watch_status(&self) -> watch::Receiver<LinkStatus> {
        self.inner.status.subscribe()
    }

    /// Handles each change of state, in order. Renewing the hub before its token runs out is not a
    /// change.
    pub fn on_status_changed<F, Fut>(&self, handler: F)
    where
        F: Fn(LinkStatus) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        lock(&self.inner.status_handlers).push(Arc::new(move |status| {
            let done = handler(status);
            Box::pin(async move {
                done.await;
                Ok(())
            })
        }));
    }

    /// Handles the server's word about its certificates, when the pins changed: a next one to trust
    /// as well, a switch to it, or a cancelled one. Save the pins in the handler. Only once every
    /// handler returned `Ok` does the link tell the server it has the next certificate; one that
    /// fails is taken as not saved.
    pub fn on_pins_changed<F, Fut, E>(&self, handler: F)
    where
        F: Fn(Pins) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), E>> + Send + 'static,
        E: Into<HandlerError>,
    {
        lock(&self.inner.pins_handlers).push(Arc::new(move |pins| {
            let done = handler(pins);
            Box::pin(async move { done.await.map_err(Into::into) })
        }));
    }

    /// Handles the server moving on the local network, when the link followed it. Save the address
    /// in the handler.
    pub fn on_address_changed<F, Fut>(&self, handler: F)
    where
        F: Fn(Url) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        lock(&self.inner.address_handlers).push(Arc::new(move |address| {
            let done = handler(address);
            Box::pin(async move {
                done.await;
                Ok(())
            })
        }));
    }

    /// Handles one of the app's own hub messages, on every hub connection the link makes. The
    /// handler gets the message's arguments and runs for one message at a time.
    ///
    /// # Panics
    ///
    /// When the name is empty or starts with `Skakel`, which are Skakel's own.
    pub fn on<F, Fut>(&self, method: &str, handler: F) -> Subscription
    where
        F: Fn(Vec<Value>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        check_name(method);
        let id = self.inner.next_message_id.fetch_add(1, Ordering::Relaxed);
        lock(&self.inner.messages).push(MessageHandler {
            id,
            method: method.to_owned(),
            handler: Arc::new(move |arguments| {
                let done = handler(arguments);
                Box::pin(async move {
                    done.await;
                    Ok(())
                })
            }),
        });
        Subscription {
            inner: Arc::downgrade(&self.inner),
            id,
        }
    }

    /// Starts keeping the hub connected, in the background. Handlers report how it goes. Starting a
    /// started link does nothing.
    pub fn start(&self) {
        let mut run = lock(&self.inner.run);
        if run.is_some() {
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

    /// Closes the hub and stops trying. Streams already open carry on.
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

    /// Checks the version and the credentials with `GET /skakel/v1/hello`, as an app's Test button
    /// does. Works whether the link is started or not.
    pub async fn hello(&self) -> Result<SkakelHello> {
        let address = self.address();
        let result = async {
            let info = read_info_with(
                &self.inner.http,
                &address,
                self.inner.options.request_timeout,
            )
            .await?;
            require_version(&info.versions)?;
            let token = self.inner.tokens.get().await?;
            let response = self
                .inner
                .http
                .get(address.join(HELLO_PATH).map_err(Error::from_cause)?)
                .timeout(self.inner.options.request_timeout)
                .bearer_auth(&token.value)
                .send()
                .await
                .map_err(Error::from_cause)?;
            if response.status() == StatusCode::UNAUTHORIZED {
                self.inner.tokens.forget(&token.value).await;
            }
            let hello: SkakelHello = http::read_json(response).await?;
            if hello.server.is_empty() || hello.client_id.is_empty() {
                return Err(bad_answer(
                    "The hello answer is missing the server or the client.",
                ));
            }
            Ok(hello)
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

    /// Sends a request to one of the app's own endpoints on this server: pinned, with the link's
    /// token on it, and the server's address as its base. `path` is the path and query, starting
    /// with `/`, so the token cannot leave for another host. `configure` adds the body and headers.
    /// A 401 drops the token, so the next call gets a new one.
    ///
    /// # Panics
    ///
    /// When `path` does not start with a single `/`.
    pub async fn request(
        &self,
        method: Method,
        path: &str,
        configure: impl FnOnce(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
    ) -> Result<reqwest::Response> {
        assert!(
            path.starts_with('/') && !path.starts_with("//") && !path.contains('\\'),
            "A link's requests go to a path on its server, such as /skakel/v1/hello."
        );
        let address = self.address();
        let url = address.join(path).map_err(Error::from_cause)?;
        assert!(
            is_at(&url, &address),
            "A link's requests stay on its server."
        );
        let result = async {
            let token = self.inner.tokens.get().await?;
            let builder = self
                .inner
                .http
                .request(method, url)
                .timeout(self.inner.options.request_timeout)
                .bearer_auth(&token.value);
            let response = configure(builder).send().await.map_err(Error::from_cause)?;
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

    /// Calls one of the app's own hub methods and waits for its result.
    ///
    /// # Panics
    ///
    /// When the name is empty or starts with `Skakel`.
    pub async fn invoke(&self, method: &str, arguments: Vec<Value>) -> Result<Value, InvokeError> {
        check_name(method);
        let hub = self.connected_hub().await?;
        hub.invoke(method, arguments).await
    }

    /// Calls one of the app's own hub methods and reads its result as `T`.
    pub async fn invoke_as<T: DeserializeOwned>(
        &self,
        method: &str,
        arguments: Vec<Value>,
    ) -> Result<T, InvokeError> {
        let value = self.invoke(method, arguments).await?;
        serde_json::from_value(value).map_err(|e| InvokeError::Failed(Error::from_cause(e)))
    }

    /// Sends one of the app's own hub messages without waiting for it to run.
    ///
    /// # Panics
    ///
    /// When the name is empty or starts with `Skakel`.
    pub async fn send(&self, method: &str, arguments: Vec<Value>) -> Result<()> {
        check_name(method);
        let hub = self.connected_hub().await?;
        hub.send(method, arguments)
    }

    /// Opens a stream at `/skakel/v1/streams/{type}` with the link's token. What the stream is for
    /// goes in `query`, as the type defines it. A refusal before the upgrade comes back in the
    /// result, with the server's status and its words for it.
    ///
    /// # Panics
    ///
    /// When `stream_type` is not one or more of `a-z`, `0-9` and `-`.
    pub async fn open_stream(
        &self,
        stream_type: &str,
        query: &[(&str, &str)],
    ) -> Result<OpenResult<StreamConnection>> {
        assert!(
            is_stream_type(stream_type),
            "A stream type is one or more of a-z, 0-9 and -."
        );
        let address = self.address();
        let result = async {
            let mut attempt = 1;
            loop {
                let token = self.inner.tokens.get().await?;
                let result = streams::open(
                    &self.inner.http,
                    &address,
                    stream_type,
                    query,
                    &token.value,
                    self.inner.options.request_timeout,
                )
                .await?;
                if let OpenResult::Refused(refusal) = &result {
                    if refusal.status == 401 && attempt == 1 {
                        // The token may have just run out on the server's clock; one more try with a
                        // fresh one.
                        self.inner.tokens.forget(&token.value).await;
                        attempt += 1;
                        continue;
                    }
                    log::info!(
                        "{} refused a {stream_type} stream with {}: {}",
                        http::authority(&address),
                        refusal.status,
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
    /// the server to say the port is open. A second client gets a refusal with 409.
    ///
    /// # Panics
    ///
    /// When `port_id` is empty.
    pub async fn open_serial(&self, port_id: &str) -> Result<OpenResult<SerialConnection>> {
        assert!(!port_id.is_empty(), "Name the port.");
        match self
            .open_stream(STREAM_TYPE, &[(PORT_QUERY, port_id)])
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

    /// The live hub connection. While the link is connected and renewing, waits for the new one.
    async fn connected_hub(&self) -> Result<Arc<HubConnection>> {
        let mut hub = self.inner.hub.subscribe();
        let mut status = self.inner.status.subscribe();
        loop {
            if status.borrow_and_update().state != LinkState::Connected {
                return Err(Error::of(FailureKind::NotConnected));
            }
            if let Some(connection) = hub.borrow_and_update().clone() {
                return Ok(connection);
            }
            tokio::select! {
                _ = hub.changed() => {}
                _ = status.changed() => {}
            }
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

/// The path under `/skakel/v1/`, checked as the server checks it.
fn hub_path(path: &str) -> String {
    let relative = path.trim_matches('/');
    assert!(
        !relative.is_empty()
            && !matches!(
                relative.split('/').next(),
                Some("pair" | "token" | "hello" | "streams")
            ),
        "The hub's path is the app's own, under /skakel/v1/, such as hub."
    );
    format!("{BASE_PATH}/{relative}")
}

fn check_name(method: &str) {
    assert!(
        !method.trim().is_empty() && !method.starts_with(HUB_PREFIX),
        "Names that start with {HUB_PREFIX} are Skakel's own."
    );
}

/// Calls each handler in turn. False when any failed.
async fn raise<T: Clone>(handlers: Vec<Handler<T>>, value: T) -> bool {
    let mut all_saved = true;
    for handler in handlers {
        if let Err(error) = handler(value.clone()).await {
            log::warn!("A handler failed: {error}");
            all_saved = false;
        }
    }
    all_saved
}

/// Sets the status and raises it when it changed.
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
        let handlers = lock(&inner.status_handlers).clone();
        raise(handlers, status).await;
    }
}

/// Keeps the hub connected until stopped. Catches everything: a link fails visibly, never silently.
async fn run_loop(inner: Arc<Inner>, stop: CancellationToken) {
    let mut backoff = MIN_BACKOFF;
    let mut refreshing = false;
    let mut started: Option<SystemTime> = None;
    while !stop.is_cancelled() {
        let mut address = lock(&inner.address).clone();
        // Whatever a server's tokens or closes say, connections start at most once a second.
        if let Some(started) = started {
            let since = since(inner.clock.now(), started);
            if since < MIN_BACKOFF {
                pause(&inner, MIN_BACKOFF - since, &stop).await;
                if stop.is_cancelled() {
                    return;
                }
                address = lock(&inner.address).clone();
            }
        }
        started = Some(inner.clock.now());
        match connect_once(&inner, &address, refreshing, &stop).await {
            Ok(None) => {
                refreshing = true;
                backoff = MIN_BACKOFF;
                continue;
            }
            Ok(Some(end)) => {
                refreshing = false;
                if matches!(end.kind(), FailureKind::Revoked | FailureKind::Rotated) {
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
                backoff = MIN_BACKOFF;
            }
            Err(error) => {
                if stop.is_cancelled() {
                    return;
                }
                refreshing = false;
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

        pause(&inner, backoff, &stop).await;
        if stop.is_cancelled() {
            return;
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}
/// Waits before the next try. A move ends the wait at once.
async fn pause(inner: &Inner, delay: Duration, stop: &CancellationToken) {
    tokio::select! {
        () = inner.clock.sleep(delay) => {}
        () = inner.wake.notified() => {}
        () = stop.cancelled() => {}
    }
}

/// One hub connection, from start to end. `None` when it ended because its token is about to run
/// out, so the next one is a renewal nobody hears of; otherwise why it ended. An error when it could
/// not connect.
async fn connect_once(
    inner: &Arc<Inner>,
    address: &Url,
    refreshing: bool,
    stop: &CancellationToken,
) -> Result<Option<Failure>> {
    if !refreshing {
        set_status(inner, LinkStatus::of(LinkState::Connecting)).await;
        let info = tokio::select! {
            () = stop.cancelled() => return Ok(None),
            info = read_info_with(&inner.http, address, inner.options.request_timeout) => info?,
        };
        require_version(&info.versions)?;
    }

    let attempt = Arc::new(Attempt {
        token: Mutex::new(None),
        closing: Mutex::new(None),
        presented: http::presented(),
        refresh_at: Mutex::new(SystemTime::UNIX_EPOCH),
        expires_at: Mutex::new(SystemTime::UNIX_EPOCH),
    });
    // Kept to the server's address, with no proxy, as every other request the link makes; this
    // client also tells the attempt which certificate its handshakes saw.
    let pins_fn: http::PinsFn = {
        let pins = inner.pins.clone();
        Arc::new(move || lock(&pins).clone())
    };
    let client = http::client(pins_fn, Some(attempt.presented.clone()));

    let token = tokio::select! {
        () = stop.cancelled() => return Ok(None),
        token = inner.tokens.get() => token?,
    };
    note_token(inner, &attempt, &token);
    let connecting = HubConnection::connect(
        &client,
        address,
        &inner.hub_path,
        &token.value,
        inner.options.request_timeout,
    );
    let (hub, events) = tokio::select! {
        () = stop.cancelled() => return Ok(None),
        connected = connecting => match connected {
            Ok(connected) => connected,
            Err(error) => {
                if status_of(&error) == Some(401) {
                    inner.tokens.forget(&token.value).await;
                }
                return Err(error);
            }
        },
    };
    let hub = Arc::new(hub);

    let (closed_tx, closed) = oneshot::channel();
    let dispatcher = tokio::spawn(dispatch(
        inner.clone(),
        hub.clone(),
        events,
        attempt.clone(),
        address.clone(),
        closed_tx,
    ));
    inner.hub.send_replace(Some(hub.clone()));
    lock(&inner.following).stranded = false;
    if refreshing {
        log::debug!(
            "Connected to {} again with a fresh token",
            http::authority(address)
        );
    } else {
        log::info!("Connected to {}", http::authority(address));
    }
    set_status(inner, LinkStatus::of(LinkState::Connected)).await;

    let wait = since(*lock(&attempt.refresh_at), inner.clock.now()).min(ACCESS_TOKEN_LIFETIME);
    let outcome = tokio::select! {
        () = stop.cancelled() => None,
        closed = closed => Some(Some(closed.unwrap_or(None))),
        () = inner.clock.sleep(wait) => Some(None),
    };

    // Whatever ended it, this connection is over: nobody reaches the hub through it any more.
    inner.hub.send_if_modified(|current| {
        if current.as_ref().is_some_and(|c| Arc::ptr_eq(c, &hub)) {
            *current = None;
            true
        } else {
            false
        }
    });
    hub.close().await;
    if tokio::time::timeout(Duration::from_secs(2), dispatcher)
        .await
        .is_err()
    {
        log::debug!("The hub's handlers did not finish");
    }

    let Some(outcome) = outcome else {
        return Ok(None);
    };
    let Some(error) = outcome else {
        // The token is about to run out.
        return Ok(None);
    };
    match lock(&attempt.closing).clone().as_deref() {
        Some(CLOSING_REVOKED) => return Ok(Some(Failure::of(FailureKind::Revoked))),
        Some(CLOSING_ROTATED) => return Ok(Some(Failure::of(FailureKind::Rotated))),
        Some(CLOSING_STOPPING) => return Ok(Some(Failure::of(FailureKind::ServerStopping))),
        _ => {}
    }
    let expires_at = *lock(&attempt.expires_at);
    if inner.clock.now() >= expires_at - EXPIRY_GRACE {
        // The server closed it at the token's end, a little before the renewal was due.
        return Ok(None);
    }
    if let Some(text) = error {
        log::info!(
            "The hub connection to {} closed with an error: {text}",
            http::authority(address)
        );
    }
    Ok(Some(Failure::of(FailureKind::ConnectionLost)))
}

/// Notes the token an attempt connects with, and when to connect again: half a minute ahead of its
/// end; a token with less than a minute left is renewed halfway through what it has.
fn note_token(inner: &Inner, attempt: &Attempt, token: &Token) {
    let left = since(token.expires_at, inner.clock.now());
    let margin = REFRESH_AHEAD.min(left / 2);
    *lock(&attempt.token) = Some(token.value.clone());
    *lock(&attempt.refresh_at) = token.expires_at - margin;
    *lock(&attempt.expires_at) = token.expires_at;
}

fn status_of(error: &Error) -> Option<u16> {
    let mut cause = std::error::Error::source(error);
    while let Some(e) = cause {
        if let Some(StatusError(status)) = e.downcast_ref::<StatusError>() {
            return Some(*status);
        }
        cause = e.source();
    }
    None
}

/// Runs what the hub says, one message at a time and in order, until the connection ends.
async fn dispatch(
    inner: Arc<Inner>,
    hub: Arc<HubConnection>,
    mut events: tokio::sync::mpsc::UnboundedReceiver<HubEvent>,
    attempt: Arc<Attempt>,
    address: Url,
    closed: oneshot::Sender<Option<String>>,
) {
    while let Some(event) = events.recv().await {
        match event {
            HubEvent::Invocation {
                target,
                arguments,
                invocation_id,
            } => {
                if invocation_id.is_some() {
                    log::warn!(
                        "The server called {target} and waits for a result, which the client does not give"
                    );
                }
                match target.as_str() {
                    HUB_CERTIFICATES => {
                        learn_certificates(&inner, &hub, &address, &attempt, arguments.first())
                            .await
                    }
                    HUB_CLOSING => {
                        let reason = arguments
                            .first()
                            .and_then(|a| serde_json::from_value::<SkakelClosing>(a.clone()).ok())
                            .map(|c| c.reason);
                        log::info!(
                            "{} is closing the connection: {}",
                            http::authority(&address),
                            reason.as_deref().unwrap_or("?")
                        );
                        *lock(&attempt.closing) = reason;
                    }
                    _ if target.starts_with(HUB_PREFIX) => {
                        log::debug!("Ignored the server's {target}");
                    }
                    _ => {
                        let handlers: Vec<Handler<Vec<Value>>> = lock(&inner.messages)
                            .iter()
                            .filter(|m| m.method == target)
                            .map(|m| m.handler.clone())
                            .collect();
                        raise(handlers, arguments).await;
                    }
                }
            }
            HubEvent::Closed { error } => {
                let _ = closed.send(error);
                return;
            }
        }
    }
    let _ = closed.send(None);
}

/// The server told the link which certificate it presents and which one it will switch to. The link
/// is pinned to a certificate it trusts, so it may vouch for the next one: it is trusted as well, or
/// becomes the pinned one once the server presents it. Once the app saved the pins, the server is
/// told the client has the next one. A fingerprint that is not one is ignored. So is a statement
/// about a certificate this connection did not present, unless a new connection to the server
/// presents it, as after a switch, when the hub connection still runs on the old certificate.
async fn learn_certificates(
    inner: &Arc<Inner>,
    hub: &HubConnection,
    address: &Url,
    attempt: &Attempt,
    argument: Option<&Value>,
) {
    let Some(certificates) =
        argument.and_then(|a| serde_json::from_value::<SkakelCertificates>(a.clone()).ok())
    else {
        log::warn!("The server sent certificates that are not fingerprints; ignored");
        return;
    };
    if fingerprints::normalize(&certificates.fingerprint).is_none()
        || certificates
            .next_fingerprint
            .as_deref()
            .is_some_and(|next| fingerprints::normalize(next).is_none())
    {
        log::warn!("The server sent certificates that are not fingerprints; ignored");
        return;
    }

    let presented = http::last_presented(&attempt.presented);
    let on_this_connection = presented
        .as_deref()
        .is_some_and(|p| fingerprints::are_equal(&certificates.fingerprint, p));
    if !on_this_connection && !presents(inner, address, &certificates.fingerprint).await {
        log::warn!(
            "The server spoke of its certificate {}, which it does not present; ignored",
            certificates.fingerprint
        );
        return;
    }

    let (before, after) = {
        let mut pins = lock(&inner.pins);
        let before = pins.clone();
        let after = before.with_server_certificates(
            &certificates.fingerprint,
            certificates.next_fingerprint.as_deref(),
        );
        *pins = after.clone();
        (before, after)
    };
    if after != before {
        log::info!(
            "The server's certificates changed: pinned {}, next {}",
            after.fingerprint(),
            after.next_fingerprint().unwrap_or("none")
        );
        let handlers = lock(&inner.pins_handlers).clone();
        if !raise(handlers, after.clone()).await {
            // Not saved: the server is not told, and says it again on the next connection.
            return;
        }
    }

    if let (Some(next), Some(said)) = (
        after.next_fingerprint(),
        certificates.next_fingerprint.as_deref(),
    ) && fingerprints::are_equal(next, said)
    {
        // Sent, not invoked: a handler that waits for an answer would hold up the messages that
        // bring it.
        if let Err(error) = hub.send(
            HUB_NEXT_CERTIFICATE_RECEIVED,
            vec![Value::String(next.to_owned())],
        ) {
            log::info!(
                "{HUB_NEXT_CERTIFICATE_RECEIVED} on {} failed: {error:?}",
                http::authority(address)
            );
        }
    }
}

/// Whether a new connection to `address`, pinned as the link is, presents the certificate
/// `fingerprint`. Within five seconds, as a move's proof.
async fn presents(inner: &Inner, address: &Url, fingerprint: &str) -> bool {
    let presented = http::presented();
    let pins_fn: http::PinsFn = {
        let pins = inner.pins.clone();
        Arc::new(move || lock(&pins).clone())
    };
    let client = http::client(pins_fn, Some(presented.clone()));
    let Ok(url) = address.join(INFO_PATH) else {
        return false;
    };
    match client.get(url).timeout(PROOF_TIMEOUT).send().await {
        Ok(_) => http::last_presented(&presented)
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
    let handlers = lock(&inner.address_handlers).clone();
    raise(handlers, to).await;
}

/// Whether `url` holds a certificate the link trusts: `GET /skakel/info` over the pinned client,
/// with no token, within five seconds. Any answer after the pinned handshake proves it; a handshake
/// that fails or takes too long does not.
fn proves(inner: &Arc<Inner>, url: Url) -> impl Future<Output = bool> + use<> {
    let http = inner.http.clone();
    async move {
        let Ok(info) = url.join(INFO_PATH) else {
            return false;
        };
        match http.get(info).timeout(PROOF_TIMEOUT).send().await {
            Ok(_) => true,
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
    fn hub_path_is_under_the_base_path() {
        assert_eq!(hub_path("hub"), "/skakel/v1/hub");
        assert_eq!(hub_path("/app/hub/"), "/skakel/v1/app/hub");
    }

    #[test]
    #[should_panic(expected = "The hub's path is the app's own")]
    fn hub_path_refuses_what_skakel_serves_itself() {
        hub_path("pair");
    }

    #[test]
    #[should_panic(expected = "The hub's path is the app's own")]
    fn hub_path_refuses_nothing() {
        hub_path("/");
    }

    #[test]
    #[should_panic(expected = "Skakel's own")]
    fn names_that_start_with_skakel_are_refused() {
        check_name("SkakelSomething");
    }

    #[test]
    fn an_app_name_is_taken() {
        check_name("Greet");
    }

    #[test]
    fn status_of_finds_the_status_a_call_failed_with() {
        let error = Error::from_cause(StatusError(401));

        assert_eq!(status_of(&error), Some(401));
        assert_eq!(status_of(&Error::of(FailureKind::Unreachable)), None);
    }

    #[test]
    fn link_states_compare_by_state_and_failure() {
        let a = LinkStatus::of(LinkState::Failed);
        let b = LinkStatus::with(LinkState::Failed, Failure::of(FailureKind::Unreachable));

        assert_ne!(a, b);
    }
}
