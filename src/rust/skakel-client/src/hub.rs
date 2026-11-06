//! A SignalR client for the part of the JSON hub protocol Skakel's hub uses: negotiate, the
//! handshake, invocations both ways (with and without a result), pings, and close.
//!
//! Nothing off the shelf fits. Of the Rust SignalR clients on crates.io, `signalr-client` 0.3.2
//! (MIT) builds its own `native-tls` connector and sends its negotiate through `ehttp`, with no way
//! to hand it a pinned handshake, and `signalrs-client` 0.1.1 (MIT) is on `reqwest` 0.11 and
//! `tokio-tungstenite` 0.17 with no hook for the certificate check either. Skakel's hub is pinned,
//! never follows a negotiation that points elsewhere, and renews its connection around the token's
//! lifetime, all of which need the connection under this crate's control.
//!
//! What is implemented, from the protocol's specification (`HubProtocol.md` in `dotnet/aspnetcore`):
//!
//! - `POST {hub}/negotiate?negotiateVersion=1`, with the bearer token. A negotiation that answers
//!   with a `url` (a redirect) or an `error`, or that offers no WebSockets, is a failure. The
//!   WebSocket opens at `{hub}?id={connectionToken}`.
//! - The handshake: `{"protocol":"json","version":1}` and the answer `{}`, each ended by the record
//!   separator 0x1E, as is every message after.
//! - Invocation (type 1), Completion (3) and Ping (6) both ways, and Close (7) from the server.
//!   Streaming (2, 4, 5) and acknowledgements (8, 9) are not part of Skakel's hub, and are ignored.
//! - A ping every 15 seconds, and a connection that heard nothing for 30 seconds is dead, as in
//!   the .NET client.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use reqwest::Url;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;

use crate::failure::{Error, FailureKind, bad_answer};
use crate::http;
use crate::ws::{self, Opened, Socket};

/// Ends every message.
const RECORD_SEPARATOR: char = '\u{1e}';

/// How often the client pings, so the server does not take it for dead.
const PING_EVERY: Duration = Duration::from_secs(15);

/// How long the client waits to hear anything from the server before it takes the connection for
/// dead.
const SERVER_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the server has to answer the handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// The most one hub message may be; a longer one ends the connection.
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// What a call to one of the hub's methods gave.
#[derive(Debug)]
pub enum InvokeError {
    /// The link is not connected, the connection was lost during the call, or the result was not
    /// what the caller asked for.
    Failed(Error),
    /// The hub method threw, with what the server says about it.
    Server(String),
}

impl fmt::Display for InvokeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failed(error) => error.fmt(f),
            Self::Server(text) => write!(f, "The hub method failed: {text}"),
        }
    }
}

impl std::error::Error for InvokeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Failed(error) => Some(error),
            Self::Server(_) => None,
        }
    }
}

impl From<Error> for InvokeError {
    fn from(error: Error) -> Self {
        Self::Failed(error)
    }
}

/// What a hub connection tells its owner, in the order it happened.
#[derive(Debug)]
pub(crate) enum HubEvent {
    /// The server called one of the client's methods.
    Invocation {
        target: String,
        arguments: Vec<Value>,
        /// Set when the server waits for a result, which the client cannot give.
        invocation_id: Option<String>,
    },
    /// The connection ended. `error` is why, when it was not a close the client asked for.
    Closed { error: Option<String> },
}

enum Command {
    Send(String),
    Close,
}

type Pending = Arc<Mutex<HashMap<String, oneshot::Sender<Result<Value, String>>>>>;

/// One hub connection. Dropping it ends it.
pub(crate) struct HubConnection {
    commands: mpsc::UnboundedSender<Command>,
    next_id: AtomicU64,
    pending: Pending,
    task: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Negotiation {
    connection_token: Option<String>,
    connection_id: Option<String>,
    #[serde(default)]
    available_transports: Vec<Transport>,
    url: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct Transport {
    transport: String,
}

impl HubConnection {
    /// Negotiates, opens the WebSocket and does the handshake. `server` is the server's base
    /// address and `hub` the hub's path under it, such as `/skakel/v1/hub`.
    pub async fn connect(
        client: &reqwest::Client,
        server: &Url,
        hub: &str,
        token: &str,
        timeout: Duration,
    ) -> Result<(Self, mpsc::UnboundedReceiver<HubEvent>), Error> {
        let hub_url = server
            .join(hub.trim_start_matches('/'))
            .map_err(Error::from_cause)?;

        let mut negotiate_url = hub_url.clone();
        negotiate_url
            .path_segments_mut()
            .map_err(|()| bad_answer("The hub's address cannot take a path."))?
            .push("negotiate");
        negotiate_url
            .query_pairs_mut()
            .append_pair("negotiateVersion", "1");
        let response = client
            .post(negotiate_url)
            .timeout(timeout)
            .bearer_auth(token)
            .send()
            .await
            .map_err(Error::from_cause)?;
        let negotiation: Negotiation = http::read_json(response).await?;
        if negotiation.url.is_some() {
            // A server that sends the client elsewhere is not followed.
            return Err(bad_answer(
                "The hub's negotiation pointed away from the server's own address.",
            ));
        }
        if let Some(error) = negotiation.error {
            return Err(bad_answer(format!("The hub's negotiation failed: {error}")));
        }
        if !negotiation
            .available_transports
            .iter()
            .any(|t| t.transport == "WebSockets")
        {
            return Err(bad_answer("The hub does not offer WebSockets."));
        }
        let id = negotiation
            .connection_token
            .or(negotiation.connection_id)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| bad_answer("The hub's negotiation gave no connection."))?;

        let mut socket_url = hub_url;
        socket_url.query_pairs_mut().append_pair("id", &id);
        let mut socket =
            match ws::open(client, socket_url, token, timeout, MAX_MESSAGE_BYTES).await? {
                Opened::Open(socket) => socket,
                Opened::Refused { status, .. } => {
                    return Err(Error::from_cause(crate::failure::StatusError(status)));
                }
            };

        tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake(&mut socket))
            .await
            .map_err(Error::from_cause)??;

        let (commands, commands_rx) = mpsc::unbounded_channel();
        let (events, events_rx) = mpsc::unbounded_channel();
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let task = tokio::spawn(run(socket, commands_rx, events, pending.clone()));
        Ok((
            Self {
                commands,
                next_id: AtomicU64::new(1),
                pending,
                task: Mutex::new(Some(task)),
            },
            events_rx,
        ))
    }

    /// Calls a hub method and waits for its result.
    pub async fn invoke(&self, target: &str, arguments: Vec<Value>) -> Result<Value, InvokeError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed).to_string();
        let (done, result) = oneshot::channel();
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id.clone(), done);
        let message =
            json!({ "type": 1, "invocationId": id, "target": target, "arguments": arguments });
        if self
            .commands
            .send(Command::Send(message.to_string()))
            .is_err()
        {
            self.pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&id);
            return Err(Error::of(FailureKind::ConnectionLost).into());
        }
        match result.await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(InvokeError::Server(error)),
            // The connection ended and dropped the call.
            Err(_) => Err(Error::of(FailureKind::ConnectionLost).into()),
        }
    }

    /// Calls a hub method without waiting for it to run.
    pub fn send(&self, target: &str, arguments: Vec<Value>) -> Result<(), Error> {
        let message = json!({ "type": 1, "target": target, "arguments": arguments });
        self.commands
            .send(Command::Send(message.to_string()))
            .map_err(|_| Error::of(FailureKind::ConnectionLost))
    }

    /// Closes the connection and waits briefly for it to end.
    pub async fn close(&self) {
        let _ = self.commands.send(Command::Close);
        let task = self.task.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(mut task) = task
            && tokio::time::timeout(Duration::from_secs(2), &mut task)
                .await
                .is_err()
        {
            task.abort();
        }
    }
}

impl Drop for HubConnection {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Close);
        if let Some(task) = self.task.get_mut().ok().and_then(Option::take) {
            // The task ends by itself once it sees the close; a stuck one is cut off.
            tokio::spawn(async move {
                let mut task = task;
                if tokio::time::timeout(Duration::from_secs(2), &mut task)
                    .await
                    .is_err()
                {
                    task.abort();
                }
            });
        }
    }
}

fn record(json: &str) -> Message {
    Message::text(format!("{json}{RECORD_SEPARATOR}"))
}

/// Sends the protocol and reads the server's answer: `{}`, or an error.
async fn handshake(socket: &mut Socket) -> Result<(), Error> {
    socket
        .send(record(r#"{"protocol":"json","version":1}"#))
        .await
        .map_err(Error::from_cause)?;
    loop {
        let Some(message) = socket.next().await else {
            return Err(Error::of(FailureKind::ConnectionLost));
        };
        match message.map_err(Error::from_cause)? {
            Message::Text(text) => {
                let first = text.split(RECORD_SEPARATOR).next().unwrap_or_default();
                let answer: Value = serde_json::from_str(first).map_err(Error::from_cause)?;
                return match answer.get("error") {
                    Some(error) => Err(bad_answer(format!(
                        "The hub refused the handshake: {error}"
                    ))),
                    None => Ok(()),
                };
            }
            Message::Close(_) => return Err(Error::of(FailureKind::ConnectionLost)),
            _ => {}
        }
    }
}

/// Owns the socket until the connection ends, then says so.
async fn run(
    mut socket: Socket,
    mut commands: mpsc::UnboundedReceiver<Command>,
    events: mpsc::UnboundedSender<HubEvent>,
    pending: Pending,
) {
    let mut ping = tokio::time::interval(PING_EVERY);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping.reset();
    let heard = tokio::time::sleep(SERVER_TIMEOUT);
    tokio::pin!(heard);
    let mut closing = false;
    let error: Option<String> = loop {
        tokio::select! {
            message = socket.next() => {
                heard.as_mut().reset(tokio::time::Instant::now() + SERVER_TIMEOUT);
                match message {
                    None => break if closing { None } else { Some("The connection ended.".to_owned()) },
                    Some(Err(error)) => break if closing { None } else { Some(error.to_string()) },
                    Some(Ok(Message::Text(text))) => {
                        match handle_records(&text, &events, &pending) {
                            Flow::Continue => {}
                            Flow::Closed(error) => break error,
                        }
                    }
                    Some(Ok(Message::Close(_))) => break if closing { None } else { Some("The server closed the connection.".to_owned()) },
                    // Pings are answered by the library; the rest is not part of the protocol.
                    Some(Ok(_)) => {}
                }
            }
            command = commands.recv() => match command {
                Some(Command::Send(text)) => {
                    if let Err(error) = socket.send(record(&text)).await {
                        break Some(error.to_string());
                    }
                }
                Some(Command::Close) | None => {
                    if closing {
                        break None;
                    }
                    closing = true;
                    let _ = socket.close(None).await;
                    // The server's close frame ends the loop; do not wait long for it.
                    heard.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(2));
                }
            },
            _ = ping.tick(), if !closing => {
                if let Err(error) = socket.send(record(r#"{"type":6}"#)).await {
                    break Some(error.to_string());
                }
            }
            () = &mut heard => {
                if closing {
                    break None;
                }
                break Some("The server stopped answering.".to_owned());
            }
        }
    };
    // Calls still waiting for a result will not get one.
    pending.lock().unwrap_or_else(|e| e.into_inner()).clear();
    let _ = events.send(HubEvent::Closed { error });
}

enum Flow {
    Continue,
    Closed(Option<String>),
}

/// Reads the messages in one frame, each ended by the record separator.
fn handle_records(text: &str, events: &mpsc::UnboundedSender<HubEvent>, pending: &Pending) -> Flow {
    for part in text.split(RECORD_SEPARATOR).filter(|part| !part.is_empty()) {
        let Ok(message) = serde_json::from_str::<Value>(part) else {
            return Flow::Closed(Some(
                "The server sent a message that is not JSON.".to_owned(),
            ));
        };
        match message.get("type").and_then(Value::as_i64) {
            Some(1) => {
                let target = message
                    .get("target")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let arguments = match message.get("arguments") {
                    Some(Value::Array(arguments)) => arguments.clone(),
                    _ => Vec::new(),
                };
                let invocation_id = message
                    .get("invocationId")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let _ = events.send(HubEvent::Invocation {
                    target,
                    arguments,
                    invocation_id,
                });
            }
            Some(3) => {
                let Some(id) = message.get("invocationId").and_then(Value::as_str) else {
                    continue;
                };
                let waiting = pending.lock().unwrap_or_else(|e| e.into_inner()).remove(id);
                if let Some(waiting) = waiting {
                    let outcome = match message.get("error").and_then(Value::as_str) {
                        Some(error) => Err(error.to_owned()),
                        None => Ok(message.get("result").cloned().unwrap_or(Value::Null)),
                    };
                    let _ = waiting.send(outcome);
                }
            }
            Some(7) => {
                let error = message
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("The server closed the connection.");
                return Flow::Closed(Some(error.to_owned()));
            }
            // Pings, and what Skakel's hub never sends.
            _ => {}
        }
    }
    Flow::Continue
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channels() -> (
        mpsc::UnboundedSender<HubEvent>,
        mpsc::UnboundedReceiver<HubEvent>,
        Pending,
    ) {
        let (tx, rx) = mpsc::unbounded_channel();
        (tx, rx, Arc::new(Mutex::new(HashMap::new())))
    }

    #[test]
    fn a_record_is_the_json_and_the_separator() {
        let Message::Text(text) = record(r#"{"type":6}"#) else {
            panic!("a text frame");
        };

        assert_eq!(text.as_str(), "{\"type\":6}\u{1e}");
    }

    #[test]
    fn an_invocation_becomes_an_event_with_its_arguments() {
        let (tx, mut rx, pending) = channels();

        let flow = handle_records(
            "{\"type\":1,\"target\":\"Greeted\",\"arguments\":[\"hi\",2]}\u{1e}",
            &tx,
            &pending,
        );

        assert!(matches!(flow, Flow::Continue));
        let Some(HubEvent::Invocation {
            target,
            arguments,
            invocation_id,
        }) = rx.try_recv().ok()
        else {
            panic!("an invocation");
        };
        assert_eq!(target, "Greeted");
        assert_eq!(arguments, [json!("hi"), json!(2)]);
        assert_eq!(invocation_id, None);
    }

    #[test]
    fn several_messages_in_one_frame_are_read_in_order() {
        let (tx, mut rx, pending) = channels();

        handle_records(
            "{\"type\":6}\u{1e}{\"type\":1,\"target\":\"A\",\"arguments\":[]}\u{1e}{\"type\":1,\"target\":\"B\",\"arguments\":[]}\u{1e}",
            &tx,
            &pending,
        );

        let targets: Vec<String> = std::iter::from_fn(|| rx.try_recv().ok())
            .filter_map(|e| match e {
                HubEvent::Invocation { target, .. } => Some(target),
                HubEvent::Closed { .. } => None,
            })
            .collect();
        assert_eq!(targets, ["A", "B"]);
    }

    #[test]
    fn a_completion_gives_its_waiting_call_the_result_or_the_error() {
        let (tx, _rx, pending) = channels();
        let (ok, mut ok_result) = oneshot::channel();
        let (bad, mut bad_result) = oneshot::channel();
        pending.lock().unwrap().insert("1".into(), ok);
        pending.lock().unwrap().insert("2".into(), bad);

        handle_records(
            "{\"type\":3,\"invocationId\":\"1\",\"result\":\"echo\"}\u{1e}{\"type\":3,\"invocationId\":\"2\",\"error\":\"boom\"}\u{1e}",
            &tx,
            &pending,
        );

        assert_eq!(ok_result.try_recv().unwrap(), Ok(json!("echo")));
        assert_eq!(bad_result.try_recv().unwrap(), Err("boom".to_owned()));
        assert!(pending.lock().unwrap().is_empty());
    }

    #[test]
    fn a_completion_without_a_result_is_null() {
        let (tx, _rx, pending) = channels();
        let (done, mut result) = oneshot::channel();
        pending.lock().unwrap().insert("1".into(), done);

        handle_records("{\"type\":3,\"invocationId\":\"1\"}\u{1e}", &tx, &pending);

        assert_eq!(result.try_recv().unwrap(), Ok(Value::Null));
    }

    #[test]
    fn a_close_message_ends_the_connection_with_its_error() {
        let (tx, _rx, pending) = channels();

        let flow = handle_records(
            "{\"type\":7,\"error\":\"shutting down\"}\u{1e}",
            &tx,
            &pending,
        );

        assert!(matches!(flow, Flow::Closed(Some(error)) if error == "shutting down"));
    }

    #[test]
    fn a_message_that_is_not_json_ends_the_connection() {
        let (tx, _rx, pending) = channels();

        assert!(matches!(
            handle_records("nope\u{1e}", &tx, &pending),
            Flow::Closed(Some(_))
        ));
    }

    #[test]
    fn pings_and_what_the_hub_never_sends_are_ignored() {
        let (tx, mut rx, pending) = channels();

        let flow = handle_records(
            "{\"type\":6}\u{1e}{\"type\":2,\"invocationId\":\"1\",\"item\":1}\u{1e}{\"type\":9}\u{1e}",
            &tx,
            &pending,
        );

        assert!(matches!(flow, Flow::Continue));
        assert!(rx.try_recv().is_err());
    }
}
