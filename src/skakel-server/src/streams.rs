//! Data streams: one WebSocket that carries one thing, opened at
//! `/skakel/v1/streams/{type}` with a bearer token.
//!
//! The app registers a handler per stream type. The handler looks at the request (the client, the
//! query string) and either refuses it, with the status and the detail a person can read, or
//! accepts it and gets a [`StreamSession`] to read and write frames on. The server pings every 15
//! seconds, gives up on a client silent for 30, and ends the session with a close code when the
//! client is revoked, its secret rotated or the server stops.

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::ws::{CloseFrame, Message, WebSocket};
use skakel_protocol::{
    CLOSE_NORMAL, STREAM_KEEP_ALIVE_INTERVAL, STREAM_KEEP_ALIVE_TIMEOUT, close_code_for,
};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use crate::sessions::Sessions;

/// How long the server waits for the client's answer to a close frame.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a handler has to return once its stream is over, before it is stopped.
const RETURN_TIMEOUT: Duration = Duration::from_secs(5);
/// Frames waiting between the WebSocket and the handler, either way. Reading stops when this
/// many wait for the handler, so a slow handler slows the client instead of losing bytes.
const QUEUE: usize = 16;

/// A boxed future, the way a handler returns an async result.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A frame on a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamMessage {
    /// A binary frame: the stream's data.
    Binary(Bytes),
    /// A text frame: one control message, a JSON object with an `op` field.
    Text(String),
}

/// What a handler is asked to open.
#[derive(Debug, Clone)]
pub struct StreamRequest {
    /// The stream type from the path.
    pub stream_type: String,
    /// The id of the client that opens it.
    pub client_id: String,
    /// The name that client was registered under.
    pub client_name: String,
    /// The address the request came from.
    pub remote: IpAddr,
    /// The query string, decoded, in the order it came.
    pub query: Vec<(String, String)>,
}

impl StreamRequest {
    /// The first value of a query parameter.
    pub fn query_value(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

type Run = Box<dyn FnOnce(StreamSession) -> BoxFuture<'static, ()> + Send>;

/// A handler's answer to a request to open a stream.
pub enum StreamOpen {
    /// Accept: the server completes the upgrade and runs this with the session.
    Accept(Run),
    /// 404: there is no such target (a port, a device).
    NotFound(String),
    /// 409: the target is in use; the detail may say who holds it.
    InUse(String),
    /// 422: the query string is not what the type expects.
    Invalid(String),
}

impl StreamOpen {
    /// Accepts the stream and runs `run` on it. When `run` returns, the server closes the
    /// stream normally (code 1000).
    pub fn accept<F, Fut>(run: F) -> Self
    where
        F: FnOnce(StreamSession) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        Self::Accept(Box::new(move |session| Box::pin(run(session))))
    }
}

/// Opens the streams of one type.
pub type StreamHandler = Arc<dyn Fn(StreamRequest) -> BoxFuture<'static, StreamOpen> + Send + Sync>;

/// The stream is over; nothing more can be sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamClosed;

impl std::fmt::Display for StreamClosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the stream is closed")
    }
}

impl std::error::Error for StreamClosed {}

enum Outgoing {
    Message(StreamMessage),
    Close { code: u16, reason: String },
}

/// The sending half of a stream. Cloneable, so one task can write while another reads.
#[derive(Clone)]
pub struct StreamWriter {
    out: mpsc::Sender<Outgoing>,
}

impl StreamWriter {
    /// Sends a frame. It waits while the client takes the frames sent before, so a slow client
    /// slows the sender. `Err` once the stream is over.
    pub async fn send(&self, message: StreamMessage) -> Result<(), StreamClosed> {
        self.out
            .send(Outgoing::Message(message))
            .await
            .map_err(|_| StreamClosed)
    }

    /// Sends a binary frame.
    pub async fn send_binary(&self, data: impl Into<Bytes>) -> Result<(), StreamClosed> {
        self.send(StreamMessage::Binary(data.into())).await
    }

    /// Sends a text frame.
    pub async fn send_text(&self, text: impl Into<String>) -> Result<(), StreamClosed> {
        self.send(StreamMessage::Text(text.into())).await
    }

    /// Closes the stream with `code` (see the close codes in `docs/protocol.md`). Frames sent
    /// before it are delivered first.
    pub async fn close(&self, code: u16, reason: &str) {
        let _ = self
            .out
            .send(Outgoing::Close {
                code,
                reason: reason.to_owned(),
            })
            .await;
    }
}

/// An accepted stream, for the handler to read and write.
pub struct StreamSession {
    /// The stream type.
    pub stream_type: String,
    /// The id of the client on the other end.
    pub client_id: String,
    /// The name that client was registered under.
    pub client_name: String,
    incoming: mpsc::Receiver<StreamMessage>,
    writer: StreamWriter,
    ending: watch::Receiver<bool>,
}

impl StreamSession {
    /// The next frame, or `None` once the stream is over: the client closed it, the server ended
    /// it (revoked, rotated, stopping), it timed out or the connection dropped. Frames that
    /// arrived before the end are still returned first.
    pub async fn recv(&mut self) -> Option<StreamMessage> {
        tokio::select! {
            biased;
            message = self.incoming.recv() => message,
            _ = self.ending.wait_for(|over| *over) => self.incoming.try_recv().ok(),
        }
    }

    /// A handle to send with, which can be cloned and moved to another task.
    pub fn writer(&self) -> StreamWriter {
        self.writer.clone()
    }

    /// Sends a frame; see [`StreamWriter::send`].
    pub async fn send(&self, message: StreamMessage) -> Result<(), StreamClosed> {
        self.writer.send(message).await
    }

    /// Sends a binary frame.
    pub async fn send_binary(&self, data: impl Into<Bytes>) -> Result<(), StreamClosed> {
        self.writer.send_binary(data).await
    }

    /// Sends a text frame.
    pub async fn send_text(&self, text: impl Into<String>) -> Result<(), StreamClosed> {
        self.writer.send_text(text).await
    }

    /// Closes the stream with `code`; see [`StreamWriter::close`].
    pub async fn close(&self, code: u16, reason: &str) {
        self.writer.close(code, reason).await;
    }

    /// Resolves when the stream is over or closing, whoever began it.
    pub async fn ended(&self) {
        let mut ending = self.ending.clone();
        let _ = ending.wait_for(|over| *over).await;
    }
}

/// Runs an accepted stream: the handler on a task of its own, the WebSocket here.
pub(crate) async fn serve(
    socket: WebSocket,
    sessions: Arc<Sessions>,
    request: StreamRequest,
    generation: u32,
    run: Run,
) {
    let (in_tx, in_rx) = mpsc::channel(QUEUE);
    let (out_tx, out_rx) = mpsc::channel(QUEUE);
    let (end_tx, end_rx) = mpsc::unbounded_channel();
    let (ending_tx, ending_rx) = watch::channel(false);
    let guard = sessions.add_stream(&request.client_id, generation, end_tx);
    let session = StreamSession {
        stream_type: request.stream_type,
        client_id: request.client_id,
        client_name: request.client_name,
        incoming: in_rx,
        writer: StreamWriter { out: out_tx },
        ending: ending_rx,
    };
    let mut handler = tokio::spawn(run(session));
    pump(socket, in_tx, out_rx, end_rx, ending_tx).await;
    if tokio::time::timeout(RETURN_TIMEOUT, &mut handler)
        .await
        .is_err()
    {
        handler.abort();
    }
    drop(guard);
}

/// Moves frames between the WebSocket and the session until the stream is over.
async fn pump(
    mut socket: WebSocket,
    in_tx: mpsc::Sender<StreamMessage>,
    mut out_rx: mpsc::Receiver<Outgoing>,
    mut end_rx: mpsc::UnboundedReceiver<String>,
    ending: watch::Sender<bool>,
) {
    let mut ping = tokio::time::interval(STREAM_KEEP_ALIVE_INTERVAL);
    ping.tick().await;
    let mut deadline = Instant::now() + STREAM_KEEP_ALIVE_TIMEOUT;
    let mut pending: Option<StreamMessage> = None;
    let mut closing_until: Option<Instant> = None;
    let (mut out_open, mut end_open) = (true, true);

    loop {
        let closing = closing_until.is_some();
        let wake = closing_until.unwrap_or(deadline);
        // While a frame waits for the handler, the client's silence is the handler's doing.
        let timed = pending.is_none() || closing;
        tokio::select! {
            biased;
            reason = end_rx.recv(), if end_open && !closing => match reason {
                Some(reason) => {
                    let code = close_code_for(&reason).unwrap_or(CLOSE_NORMAL);
                    begin_close(&mut socket, code, &reason, &mut closing_until, &ending).await;
                }
                None => end_open = false,
            },
            outgoing = out_rx.recv(), if out_open && !closing => match outgoing {
                Some(Outgoing::Message(message)) => {
                    if socket.send(to_ws(message)).await.is_err() {
                        break;
                    }
                }
                Some(Outgoing::Close { code, reason }) => {
                    begin_close(&mut socket, code, &reason, &mut closing_until, &ending).await;
                }
                None => {
                    // The handler returned and nobody else holds a writer.
                    out_open = false;
                    begin_close(&mut socket, CLOSE_NORMAL, "", &mut closing_until, &ending).await;
                }
            },
            permit = in_tx.reserve(), if pending.is_some() && !closing => match permit {
                Ok(permit) => {
                    permit.send(pending.take().expect("checked by the guard"));
                    deadline = Instant::now() + STREAM_KEEP_ALIVE_TIMEOUT;
                }
                Err(_) => pending = None,
            },
            frame = socket.recv(), if pending.is_none() => match frame {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break,
                Some(Ok(message)) => {
                    deadline = Instant::now() + STREAM_KEEP_ALIVE_TIMEOUT;
                    if !closing {
                        match message {
                            Message::Text(text) => pending = Some(StreamMessage::Text(text.to_string())),
                            Message::Binary(data) => pending = Some(StreamMessage::Binary(data)),
                            Message::Ping(_) | Message::Pong(_) | Message::Close(_) => {}
                        }
                    }
                }
            },
            _ = ping.tick(), if !closing => {
                if socket.send(Message::Ping(Bytes::new())).await.is_err() {
                    break;
                }
            }
            _ = tokio::time::sleep_until(wake), if timed => break,
        }
    }
    ending.send_replace(true);
    drain(&mut socket).await;
}

/// Lets the close handshake finish: the answer to a close frame the client sent only leaves when the
/// socket is read once more, and the client's answer to ours is read here. Anything else that arrives is
/// dropped; the stream is over.
pub(crate) async fn drain(socket: &mut WebSocket) {
    let _ = tokio::time::timeout(CLOSE_TIMEOUT / 2, async {
        while let Some(Ok(_)) = socket.recv().await {}
    })
    .await;
}

/// Sends the close frame and starts the wait for the client's.
async fn begin_close(
    socket: &mut WebSocket,
    code: u16,
    reason: &str,
    closing_until: &mut Option<Instant>,
    ending: &watch::Sender<bool>,
) {
    let frame = CloseFrame {
        code,
        reason: reason.into(),
    };
    let _ = socket.send(Message::Close(Some(frame))).await;
    *closing_until = Some(Instant::now() + CLOSE_TIMEOUT);
    ending.send_replace(true);
}

fn to_ws(message: StreamMessage) -> Message {
    match message {
        StreamMessage::Binary(data) => Message::Binary(data),
        StreamMessage::Text(text) => Message::Text(text.into()),
    }
}
