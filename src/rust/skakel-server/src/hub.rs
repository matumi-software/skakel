//! The control hub: SignalR's JSON hub protocol over a WebSocket.
//!
//! This is the subset the Skakel protocol and the .NET client use. A client negotiates
//! (`POST {hub}/negotiate`), connects a WebSocket (`GET {hub}?id=...`), sends the handshake
//! `{"protocol":"json","version":1}` and then exchanges messages, each a JSON object followed by
//! the record separator `0x1E`: invocations (type 1) and their completions (type 3), pings (type 6)
//! and the close message (type 7). Streaming invocations and other transports (server-sent events,
//! long polling) and the MessagePack protocol are not served.
//!
//! The server sends `SkakelCertificates` when a connection starts and whenever the certificates
//! change, and `SkakelClosing` before it ends a client's connection. Every other message name
//! belongs to the app, which supplies a [`HubHandler`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde_json::{Value, json};
use skakel_protocol::{
    HUB_CERTIFICATES, HUB_CLOSING, HUB_NEXT_CERTIFICATE_RECEIVED, HUB_PREFIX, SkakelClosing,
};
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::crypto::Principal;
use crate::http::{authenticate_request, problem};
use crate::server::Shared;
use crate::sessions::{HubOut, certificates_of};
use crate::streams::BoxFuture;

/// The record separator that ends every message.
const SEPARATOR: u8 = 0x1E;
/// How long a client has to send its handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// How often the server pings, and how long it waits for a sign of life from the client.
const PING_INTERVAL: Duration = Duration::from_secs(15);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a negotiation is good for before the client connects.
const NEGOTIATION_LIFETIME: Duration = Duration::from_secs(30);
/// The largest message the server reads.
const MAX_MESSAGE: usize = 1024 * 1024;

/// What a hub method answers with when it refuses: the message goes to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubError(pub String);

impl HubError {
    /// An error with this message.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for HubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for HubError {}

/// One client's connection to a hub.
#[derive(Clone)]
pub struct HubConnection {
    /// The connection's id.
    pub connection_id: String,
    /// The id of the client on the other end.
    pub client_id: String,
    /// The name that client was registered under.
    pub client_name: String,
    out: mpsc::UnboundedSender<HubOut>,
}

impl std::fmt::Debug for HubConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HubConnection")
            .field("connection_id", &self.connection_id)
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

impl HubConnection {
    /// Sends the client a message. The name belongs to the app, so one that starts with
    /// `Skakel` is refused.
    pub fn send(&self, target: &str, arguments: Vec<Value>) -> Result<(), HubError> {
        if target.starts_with(HUB_PREFIX) {
            return Err(HubError::new(format!(
                "A message name starting with {HUB_PREFIX} is Skakel's own."
            )));
        }
        self.out
            .send(HubOut::Invoke {
                target: target.to_owned(),
                arguments,
            })
            .map_err(|_| HubError::new("The connection is closed."))
    }
}

/// A call from a client to a method the app owns.
pub struct HubCall {
    /// The connection it came on.
    pub connection: HubConnection,
    /// The method's name.
    pub target: String,
    /// The arguments, as the client sent them.
    pub arguments: Vec<Value>,
}

/// The app's side of a hub: the methods clients may call.
pub trait HubHandler: Send + Sync + 'static {
    /// A client called a method. `Ok(Some(value))` answers with a result, `Ok(None)` with none,
    /// and an error is the caller's exception. An unknown method is an error too.
    fn invoke(&self, call: HubCall) -> BoxFuture<'_, Result<Option<Value>, HubError>>;

    /// A connection is up, after the server sent it the certificates.
    fn connected(&self, _connection: HubConnection) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }

    /// A connection is gone.
    fn disconnected(&self, _connection: HubConnection) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
}

/// The connections of one hub, for the app to send to.
#[derive(Clone, Default)]
pub struct HubHandle {
    connections: Arc<Mutex<HashMap<String, HubConnection>>>,
}

impl HubHandle {
    /// Everyone connected now.
    pub fn connections(&self) -> Vec<HubConnection> {
        self.connections
            .lock()
            .expect("hub lock")
            .values()
            .cloned()
            .collect()
    }

    /// Sends a message to every connection of a client. How many it reached.
    pub fn send_to_client(&self, client_id: &str, target: &str, arguments: &[Value]) -> usize {
        self.connections()
            .iter()
            .filter(|c| c.client_id == client_id)
            .filter(|c| c.send(target, arguments.to_vec()).is_ok())
            .count()
    }

    /// Sends a message to every connection. How many it reached.
    pub fn send_to_all(&self, target: &str, arguments: &[Value]) -> usize {
        self.connections()
            .iter()
            .filter(|c| c.send(target, arguments.to_vec()).is_ok())
            .count()
    }
}

struct Negotiated {
    client_id: String,
    at: Instant,
}

/// One hub: its handler, its connections and its negotiations.
pub(crate) struct HubRoute {
    shared: Arc<Shared>,
    handler: Arc<dyn HubHandler>,
    handle: HubHandle,
    negotiated: Mutex<HashMap<String, Negotiated>>,
}

impl HubRoute {
    pub(crate) fn new(
        shared: Arc<Shared>,
        handler: Arc<dyn HubHandler>,
        handle: HubHandle,
    ) -> Arc<Self> {
        Arc::new(Self {
            shared,
            handler,
            handle,
            negotiated: Mutex::new(HashMap::new()),
        })
    }

    pub(crate) fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route("/negotiate", post(negotiate))
            .route("/", get(connect))
            .with_state(self)
    }
}

#[derive(Deserialize)]
struct NegotiateQuery {
    #[serde(rename = "negotiateVersion", default)]
    version: u32,
}

#[derive(Deserialize)]
struct ConnectQuery {
    id: Option<String>,
}

fn random_id() -> String {
    URL_SAFE_NO_PAD.encode(crate::util::random::<16>())
}

async fn negotiate(
    State(route): State<Arc<HubRoute>>,
    headers: HeaderMap,
    uri: Uri,
    Query(query): Query<NegotiateQuery>,
) -> Response {
    let Some(principal) = authenticate_request(&route.shared, &headers, &uri, true) else {
        return unauthorized();
    };
    let connection_id = random_id();
    let (token, body) = if query.version >= 1 {
        let token = random_id();
        let body = json!({
            "negotiateVersion": 1,
            "connectionId": connection_id,
            "connectionToken": token,
            "availableTransports": [{ "transport": "WebSockets", "transferFormats": ["Text", "Binary"] }],
        });
        (token, body)
    } else {
        let body = json!({
            "connectionId": connection_id,
            "availableTransports": [{ "transport": "WebSockets", "transferFormats": ["Text", "Binary"] }],
        });
        (connection_id, body)
    };
    {
        let mut negotiated = route.negotiated.lock().expect("hub lock");
        let now = Instant::now();
        negotiated.retain(|_, n| n.at + NEGOTIATION_LIFETIME > now);
        negotiated.insert(
            token,
            Negotiated {
                client_id: principal.client_id,
                at: now,
            },
        );
    }
    Json(body).into_response()
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [("www-authenticate", "Bearer error=\"invalid_token\"")],
    )
        .into_response()
}

async fn connect(
    State(route): State<Arc<HubRoute>>,
    headers: HeaderMap,
    uri: Uri,
    Query(query): Query<ConnectQuery>,
    upgrade: Result<WebSocketUpgrade, axum::extract::ws::rejection::WebSocketUpgradeRejection>,
) -> Response {
    let Some(principal) = authenticate_request(&route.shared, &headers, &uri, true) else {
        return unauthorized();
    };
    let Ok(upgrade) = upgrade else {
        return problem(
            StatusCode::BAD_REQUEST,
            "The hub speaks WebSockets only. Connect with a WebSocket upgrade.",
        );
    };
    let negotiated = query
        .id
        .and_then(|id| route.negotiated.lock().expect("hub lock").remove(&id));
    match negotiated {
        Some(n)
            if n.client_id == principal.client_id
                && n.at + NEGOTIATION_LIFETIME > Instant::now() => {}
        _ => return (StatusCode::NOT_FOUND, "No connection with that ID.").into_response(),
    }
    upgrade
        .max_message_size(MAX_MESSAGE)
        .on_upgrade(move |socket| run(route, principal, socket))
}

/// A SignalR message: the JSON and the record separator.
fn record(value: &Value) -> Message {
    let mut text = value.to_string();
    text.push(char::from(SEPARATOR));
    Message::Text(text.into())
}

fn invocation(target: &str, arguments: &[Value]) -> Value {
    json!({ "type": 1, "target": target, "arguments": arguments })
}

/// Reads whole records out of what has arrived.
fn take_record(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    let end = buffer.iter().position(|b| *b == SEPARATOR)?;
    let mut record: Vec<u8> = buffer.drain(..=end).collect();
    record.pop();
    Some(record)
}

async fn run(route: Arc<HubRoute>, principal: Principal, mut socket: WebSocket) {
    let Some(mut buffer) = handshake(&mut socket).await else {
        return;
    };
    let shared = route.shared.clone();
    let loaded = shared.state.loaded();
    let Some(client) = loaded.find(&principal.client_id) else {
        return;
    };
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let connection = HubConnection {
        connection_id: random_id(),
        client_id: principal.client_id.clone(),
        client_name: client.name.clone(),
        out: out_tx.clone(),
    };
    let guard = shared
        .sessions
        .add_hub(&principal.client_id, principal.generation, out_tx);
    route
        .handle
        .connections
        .lock()
        .expect("hub lock")
        .insert(connection.connection_id.clone(), connection.clone());

    let certificates = serde_json::to_value(certificates_of(&shared.state)).expect("JSON");
    let started = socket
        .send(record(&invocation(HUB_CERTIFICATES, &[certificates])))
        .await
        .is_ok();
    if started {
        route.handler.connected(connection.clone()).await;
        serve(
            &route,
            &principal,
            &connection,
            &mut socket,
            &mut buffer,
            &mut out_rx,
        )
        .await;
        route.handler.disconnected(connection.clone()).await;
    }

    route
        .handle
        .connections
        .lock()
        .expect("hub lock")
        .remove(&connection.connection_id);
    drop(guard);
    let _ = socket.send(Message::Close(None)).await;
    crate::streams::drain(&mut socket).await;
}

/// Reads the handshake and answers it. The records that arrived after it stay in the buffer.
async fn handshake(socket: &mut WebSocket) -> Option<Vec<u8>> {
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let mut buffer = Vec::new();
    loop {
        if let Some(first) = take_record(&mut buffer) {
            let request: Value = serde_json::from_slice(&first).unwrap_or(Value::Null);
            let protocol = request.get("protocol").and_then(Value::as_str);
            let reply = match (protocol, request.get("version").and_then(Value::as_u64)) {
                (Some("json"), Some(1)) => json!({}),
                (Some("json"), _) => {
                    json!({ "error": "The server does not support version of the protocol." })
                }
                (Some(other), _) => {
                    json!({ "error": format!("The protocol '{other}' is not supported.") })
                }
                (None, _) => json!({ "error": "Handshake was canceled." }),
            };
            let ok = reply == json!({});
            socket.send(record(&reply)).await.ok()?;
            return ok.then_some(buffer);
        }
        let frame = tokio::time::timeout_at(deadline, socket.recv())
            .await
            .ok()??;
        match frame.ok()? {
            Message::Text(text) => buffer.extend_from_slice(text.as_bytes()),
            Message::Binary(data) => buffer.extend_from_slice(&data),
            Message::Close(_) => return None,
            Message::Ping(_) | Message::Pong(_) => {}
        }
        if buffer.len() > MAX_MESSAGE {
            return None;
        }
    }
}

async fn serve(
    route: &Arc<HubRoute>,
    principal: &Principal,
    connection: &HubConnection,
    socket: &mut WebSocket,
    buffer: &mut Vec<u8>,
    out_rx: &mut mpsc::UnboundedReceiver<HubOut>,
) {
    let mut ping = tokio::time::interval(PING_INTERVAL);
    ping.tick().await;
    let mut heard = Instant::now();
    let until_expiry = (principal.expires_at - OffsetDateTime::now_utc())
        .try_into()
        .unwrap_or(Duration::ZERO);
    let expiry = tokio::time::sleep(until_expiry);
    tokio::pin!(expiry);

    loop {
        // Records that came in together with the handshake or with an earlier frame.
        while let Some(message) = take_record(buffer) {
            if !handle_record(route, principal, connection, socket, &message).await {
                return;
            }
        }
        tokio::select! {
            biased;
            out = out_rx.recv() => match out {
                Some(HubOut::Invoke { target, arguments }) => {
                    if socket.send(record(&invocation(&target, &arguments))).await.is_err() {
                        return;
                    }
                }
                Some(HubOut::Closing(reason)) => {
                    let closing = serde_json::to_value(SkakelClosing { reason }).expect("JSON");
                    let _ = tokio::time::timeout(
                        Duration::from_secs(2),
                        socket.send(record(&invocation(HUB_CLOSING, &[closing]))),
                    )
                    .await;
                    let _ = socket.send(record(&json!({ "type": 7, "allowReconnect": false }))).await;
                    return;
                }
                None => return,
            },
            () = &mut expiry => {
                // The token ran out: the client connects again with a fresh one.
                let _ = socket.send(record(&json!({ "type": 7, "allowReconnect": false }))).await;
                return;
            }
            _ = ping.tick() => {
                if socket.send(record(&json!({ "type": 6 }))).await.is_err() {
                    return;
                }
            }
            () = tokio::time::sleep_until(heard + CLIENT_TIMEOUT) => return,
            frame = socket.recv() => {
                heard = Instant::now();
                match frame {
                    None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return,
                    Some(Ok(Message::Text(text))) => buffer.extend_from_slice(text.as_bytes()),
                    Some(Ok(Message::Binary(data))) => buffer.extend_from_slice(&data),
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                }
                if buffer.len() > MAX_MESSAGE {
                    return;
                }
            }
        }
    }
}

/// Acts on one message from the client. False when the connection should end.
async fn handle_record(
    route: &Arc<HubRoute>,
    principal: &Principal,
    connection: &HubConnection,
    socket: &mut WebSocket,
    message: &[u8],
) -> bool {
    let Ok(message) = serde_json::from_slice::<Value>(message) else {
        return false;
    };
    let invocation_id = message.get("invocationId").and_then(Value::as_str);
    match message.get("type").and_then(Value::as_u64) {
        Some(1) => {
            let target = message
                .get("target")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let arguments = message
                .get("arguments")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let result = call(route, principal, connection, target, arguments).await;
            if let Some(id) = invocation_id {
                let completion = match result {
                    Ok(Some(value)) => json!({ "type": 3, "invocationId": id, "result": value }),
                    Ok(None) => json!({ "type": 3, "invocationId": id }),
                    Err(error) => json!({ "type": 3, "invocationId": id, "error": error.0 }),
                };
                return socket.send(record(&completion)).await.is_ok();
            }
            true
        }
        Some(4) => {
            if let Some(id) = invocation_id {
                let completion = json!({ "type": 3, "invocationId": id, "error": "Streaming is not supported." });
                return socket.send(record(&completion)).await.is_ok();
            }
            true
        }
        Some(7) => false,
        // Pings, completions of what the server invoked, stream items and cancellations.
        _ => true,
    }
}

async fn call(
    route: &Arc<HubRoute>,
    principal: &Principal,
    connection: &HubConnection,
    target: &str,
    arguments: Vec<Value>,
) -> Result<Option<Value>, HubError> {
    if target == HUB_NEXT_CERTIFICATE_RECEIVED {
        let shared = &route.shared;
        let current = shared
            .state
            .loaded()
            .is_current(&principal.client_id, principal.generation);
        if let (true, Some(fingerprint)) = (current, arguments.first().and_then(Value::as_str))
            && !fingerprint.is_empty()
        {
            let _ = shared
                .state
                .mark_next_certificate_received(&principal.client_id, fingerprint)
                .await;
        }
        return Ok(None);
    }
    if target.starts_with(HUB_PREFIX) {
        return Err(HubError::new(format!(
            "Failed to invoke '{target}' due to an error on the server. HubException: Method does not exist."
        )));
    }
    route
        .handler
        .invoke(HubCall {
            connection: connection.clone(),
            target: target.to_owned(),
            arguments,
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_are_taken_one_at_a_time_in_order() {
        let mut buffer = b"{\"type\":6}\x1e{\"type\":1".to_vec();

        assert_eq!(take_record(&mut buffer).unwrap(), b"{\"type\":6}");
        assert_eq!(take_record(&mut buffer), None);
        buffer.extend_from_slice(b"}\x1e");
        assert_eq!(take_record(&mut buffer).unwrap(), b"{\"type\":1}");
        assert!(buffer.is_empty());
    }

    #[test]
    fn a_record_is_the_json_and_the_separator() {
        let Message::Text(text) = record(&json!({ "type": 6 })) else {
            panic!("not text");
        };

        assert_eq!(text.as_bytes(), b"{\"type\":6}\x1e");
    }

    #[test]
    fn an_invocation_names_its_target_and_arguments() {
        assert_eq!(
            invocation("Greeted", &[json!("hi")]).to_string(),
            r#"{"arguments":["hi"],"target":"Greeted","type":1}"#
        );
    }

    #[test]
    fn the_app_may_not_send_a_message_that_starts_with_skakel() {
        let (out, mut received) = mpsc::unbounded_channel();
        let connection = HubConnection {
            connection_id: "c".into(),
            client_id: "client-1".into(),
            client_name: "lab".into(),
            out,
        };

        assert!(connection.send("SkakelSomething", vec![]).is_err());
        assert!(connection.send("Greeted", vec![json!("hi")]).is_ok());
        assert!(
            matches!(received.try_recv(), Ok(HubOut::Invoke { target, .. }) if target == "Greeted")
        );
    }

    #[test]
    fn the_handle_reaches_the_connections_of_a_client() {
        let handle = HubHandle::default();
        let (a_tx, mut a_rx) = mpsc::unbounded_channel();
        let (b_tx, mut b_rx) = mpsc::unbounded_channel();
        for (id, client, out) in [("1", "client-a", a_tx), ("2", "client-b", b_tx)] {
            handle.connections.lock().unwrap().insert(
                id.into(),
                HubConnection {
                    connection_id: id.into(),
                    client_id: client.into(),
                    client_name: client.into(),
                    out,
                },
            );
        }

        assert_eq!(handle.send_to_client("client-a", "Hi", &[]), 1);
        assert!(a_rx.try_recv().is_ok());
        assert!(b_rx.try_recv().is_err());
        assert_eq!(handle.send_to_all("Hi", &[]), 2);
        assert_eq!(handle.send_to_client("client-none", "Hi", &[]), 0);
    }
}
