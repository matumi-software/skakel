//! Data streams: one WebSocket that carries one thing. Binary frames carry its data and text frames
//! its control messages, one JSON object each. Both ends ping every 15 seconds and give up after 30
//! without an answer.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use reqwest::Url;
use skakel_protocol::{
    CLOSE_FIRST_TYPE_DEFINED, CLOSE_LAST_TYPE_DEFINED, CLOSE_NORMAL, CLOSE_REVOKED, CLOSE_ROTATED,
    CLOSE_STOPPING, CLOSE_TARGET_GONE, STREAM_KEEP_ALIVE_INTERVAL, STREAM_KEEP_ALIVE_TIMEOUT,
    STREAMS_PATH,
};
use tokio::sync::{Mutex, mpsc, watch};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

use crate::failure::{Error, Failure, FailureKind};
use crate::ws::{self, Opened, Socket};

/// How long a close may wait for the server's answer.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

/// The most one stream message may be.
const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// How many frames wait for the app to read them. When the app stops reading, the connection stops
/// reading the socket, and the server slows down instead of the client losing data.
const INCOMING_FRAMES: usize = 16;

/// A frame of an open stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// Data, the stream's own bytes.
    Binary(Vec<u8>),
    /// A control message, one JSON object.
    Text(String),
}

/// Why a stream ended, by its close code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamCloseReason {
    /// 1000: closed normally.
    Normal,
    /// 4001: the client was revoked.
    Revoked,
    /// 4002: the client's secret was rotated.
    Rotated,
    /// 4003: the server is stopping, or no longer serves this type.
    ServerStopping,
    /// 4004: the target went away, such as a device that was unplugged.
    TargetGone,
    /// 4100 to 4999: a code the stream type defines. [`StreamClose::code`] says which.
    TypeDefined,
    /// The connection ended without a close frame, or a peer stopped answering pings.
    ConnectionLost,
    /// Any other code.
    Other,
}

/// How a stream ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamClose {
    /// The close code as a reason a client acts on.
    pub reason: StreamCloseReason,
    /// The close code, or `None` when there was no close frame.
    pub code: Option<u16>,
    /// The server's reason text, for the log only.
    pub description: Option<String>,
}

impl StreamClose {
    /// The close for a code, or for none when the connection just ended.
    pub fn from_code(code: Option<u16>, description: Option<String>) -> Self {
        let reason = match code {
            None | Some(1006) => StreamCloseReason::ConnectionLost,
            Some(CLOSE_NORMAL) => StreamCloseReason::Normal,
            Some(CLOSE_REVOKED) => StreamCloseReason::Revoked,
            Some(CLOSE_ROTATED) => StreamCloseReason::Rotated,
            Some(CLOSE_STOPPING) => StreamCloseReason::ServerStopping,
            Some(CLOSE_TARGET_GONE) => StreamCloseReason::TargetGone,
            Some(CLOSE_FIRST_TYPE_DEFINED..=CLOSE_LAST_TYPE_DEFINED) => {
                StreamCloseReason::TypeDefined
            }
            Some(_) => StreamCloseReason::Other,
        };
        Self {
            reason,
            code,
            description,
        }
    }

    /// What to tell a person, in fixed wording.
    pub fn message(&self) -> String {
        match self.reason {
            StreamCloseReason::Normal => "The stream closed.".to_owned(),
            StreamCloseReason::Revoked => Failure::of(FailureKind::Revoked).message().to_owned(),
            StreamCloseReason::Rotated => Failure::of(FailureKind::Rotated).message().to_owned(),
            StreamCloseReason::ServerStopping => {
                "The server stopped serving this stream.".to_owned()
            }
            StreamCloseReason::TargetGone => {
                "What the stream was for went away on the server.".to_owned()
            }
            StreamCloseReason::ConnectionLost => Failure::of(FailureKind::ConnectionLost)
                .message()
                .to_owned(),
            StreamCloseReason::TypeDefined | StreamCloseReason::Other => format!(
                "The server closed the stream with code {}.",
                self.code.unwrap_or_default()
            ),
        }
    }
}

/// Why the server refused to open a stream, by the HTTP status it answered before the upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamRefusalReason {
    /// 400: the request was not a WebSocket upgrade.
    NotAnUpgrade,
    /// 401: no token, an expired one, or one from an older generation.
    Unauthorized,
    /// 404: the server has no such type, or no such target.
    NotFound,
    /// 409: the target is in use. [`StreamRefusal::message`] names who holds it, when the app
    /// allows that.
    InUse,
    /// 422: the query string is not what the type expects.
    InvalidQuery,
    /// Any other status.
    Other,
}

/// The server refused to open a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamRefusal {
    /// The HTTP status.
    pub status: u16,
    /// The status as a reason.
    pub reason: StreamRefusalReason,
    /// The problem's `detail`, which the server wrote for a person, or fixed wording when it sent
    /// none.
    pub message: String,
}

impl StreamRefusal {
    /// The refusal for a status and the problem's detail, when there was one.
    pub fn from_status(status: u16, detail: Option<&str>) -> Self {
        let reason = match status {
            400 => StreamRefusalReason::NotAnUpgrade,
            401 => StreamRefusalReason::Unauthorized,
            404 => StreamRefusalReason::NotFound,
            409 => StreamRefusalReason::InUse,
            422 => StreamRefusalReason::InvalidQuery,
            _ => StreamRefusalReason::Other,
        };
        let message = match detail.map(str::trim).filter(|d| !d.is_empty()) {
            Some(detail) => detail.to_owned(),
            None => match reason {
                StreamRefusalReason::Unauthorized => {
                    Failure::of(FailureKind::ClientUnknown).message().to_owned()
                }
                StreamRefusalReason::NotFound => {
                    "The server has no such stream or target.".to_owned()
                }
                StreamRefusalReason::InUse => "Someone else is using it.".to_owned(),
                StreamRefusalReason::InvalidQuery => {
                    "The server did not understand what the stream was asked for.".to_owned()
                }
                _ => format!("The server refused the stream ({status})."),
            },
        };
        Self {
            status,
            reason,
            message,
        }
    }
}

/// What opening a stream gave: the stream, or the server's refusal.
#[derive(Debug)]
pub enum OpenResult<T> {
    /// The stream opened.
    Opened(T),
    /// The server refused, with its status and its words for it.
    Refused(StreamRefusal),
}

impl<T> OpenResult<T> {
    /// True when the stream opened.
    pub fn is_open(&self) -> bool {
        matches!(self, Self::Opened(_))
    }

    /// The stream, when it opened.
    pub fn stream(self) -> Option<T> {
        match self {
            Self::Opened(stream) => Some(stream),
            Self::Refused(_) => None,
        }
    }

    /// Why the server refused, when it did.
    pub fn refusal(&self) -> Option<&StreamRefusal> {
        match self {
            Self::Opened(_) => None,
            Self::Refused(refusal) => Some(refusal),
        }
    }
}

enum Command {
    Send(Message),
    Close,
}

/// An open stream. Dropping it ends the connection without a close frame; use
/// [`close`](Self::close) to end it properly.
#[derive(Debug)]
pub struct StreamConnection {
    stream_type: String,
    commands: mpsc::Sender<Command>,
    incoming: Mutex<mpsc::Receiver<Frame>>,
    closed: watch::Receiver<Option<StreamClose>>,
    task: tokio::task::AbortHandle,
}

impl Drop for StreamConnection {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl StreamConnection {
    fn start(stream_type: &str, socket: Socket) -> Self {
        let (commands, commands_rx) = mpsc::channel(INCOMING_FRAMES);
        let (incoming_tx, incoming) = mpsc::channel(INCOMING_FRAMES);
        let (closed_tx, closed) = watch::channel(None);
        let task = tokio::spawn(run(socket, commands_rx, incoming_tx, closed_tx));
        Self {
            stream_type: stream_type.to_owned(),
            commands,
            incoming: Mutex::new(incoming),
            closed,
            task: task.abort_handle(),
        }
    }

    /// The stream type.
    pub fn stream_type(&self) -> &str {
        &self.stream_type
    }

    /// Sends data. Frames go out in the order they were sent, control messages among them, so a
    /// control message takes effect between the bytes sent before it and the bytes sent after it.
    pub async fn send_binary(&self, data: impl Into<Vec<u8>>) -> Result<(), Error> {
        self.send(Message::binary(data.into())).await
    }

    /// Sends a control message, one JSON object.
    pub async fn send_text(&self, text: impl Into<String>) -> Result<(), Error> {
        self.send(Message::text(text.into())).await
    }

    async fn send(&self, message: Message) -> Result<(), Error> {
        self.commands
            .send(Command::Send(message))
            .await
            .map_err(|_| Error::of(FailureKind::ConnectionLost))
    }

    /// The next frame, or `None` once the stream has ended and everything was read. One task at a
    /// time reads.
    pub async fn recv(&self) -> Option<Frame> {
        self.incoming.lock().await.recv().await
    }

    /// Why the stream ended, once it has: the server's close code as a reason. `None` while it is
    /// open.
    pub fn close_info(&self) -> Option<StreamClose> {
        self.closed.borrow().clone()
    }

    /// Waits until the stream has ended, and says how.
    pub async fn closed(&self) -> StreamClose {
        let mut closed = self.closed.clone();
        match closed.wait_for(Option::is_some).await {
            Ok(close) => close
                .clone()
                .unwrap_or_else(|| StreamClose::from_code(None, None)),
            Err(_) => StreamClose::from_code(None, None),
        }
    }

    /// Closes the stream normally and waits briefly for the server to answer. Never fails for a
    /// stream that is already gone.
    pub async fn close(&self) {
        let _ = self.commands.send(Command::Close).await;
        let _ =
            tokio::time::timeout(CLOSE_TIMEOUT + Duration::from_millis(500), self.closed()).await;
    }
}

/// Owns the socket until the stream ends, then says how.
async fn run(
    mut socket: Socket,
    mut commands: mpsc::Receiver<Command>,
    incoming: mpsc::Sender<Frame>,
    closed: watch::Sender<Option<StreamClose>>,
) {
    let mut ping = tokio::time::interval(STREAM_KEEP_ALIVE_INTERVAL);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping.reset();
    let silent = tokio::time::sleep(STREAM_KEEP_ALIVE_TIMEOUT);
    tokio::pin!(silent);
    let mut permit = None;
    let mut we_closed = false;
    let mut received: Option<StreamClose> = None;
    loop {
        tokio::select! {
            room = incoming.reserve(), if permit.is_none() => {
                match room {
                    Ok(room) => permit = Some(room),
                    // Nobody reads any more.
                    Err(_) => break,
                }
            }
            message = socket.next(), if permit.is_some() => {
                silent.as_mut().reset(tokio::time::Instant::now() + STREAM_KEEP_ALIVE_TIMEOUT);
                match message {
                    Some(Ok(Message::Binary(data))) => {
                        if let Some(room) = permit.take() {
                            room.send(Frame::Binary(data.to_vec()));
                        }
                    }
                    Some(Ok(Message::Text(text))) => {
                        if let Some(room) = permit.take() {
                            room.send(Frame::Text(text.as_str().to_owned()));
                        }
                    }
                    Some(Ok(Message::Close(frame))) => {
                        received = Some(StreamClose::from_code(
                            Some(frame.as_ref().map_or(1005, |f| u16::from(f.code))),
                            frame.map(|f| f.reason.as_str().to_owned()).filter(|r| !r.is_empty()),
                        ));
                        // Answer it, so the close completes on both ends.
                        let _ = tokio::time::timeout(CLOSE_TIMEOUT, socket.close(None)).await;
                        break;
                    }
                    // Pings are answered by the library, and pongs only show the peer is there.
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => break,
                }
            }
            command = commands.recv() => match command {
                Some(Command::Send(message)) => {
                    if socket.send(message).await.is_err() {
                        break;
                    }
                }
                Some(Command::Close) => {
                    if we_closed {
                        continue;
                    }
                    we_closed = true;
                    let frame = CloseFrame { code: CloseCode::Normal, reason: "".into() };
                    if socket.send(Message::Close(Some(frame))).await.is_err() {
                        break;
                    }
                    // The server's close frame ends the loop; do not wait long for it.
                    silent.as_mut().reset(tokio::time::Instant::now() + CLOSE_TIMEOUT);
                }
                // Dropped: nobody sends or closes any more, but frames may still arrive.
                None => {
                    if !we_closed {
                        we_closed = true;
                        let _ = socket.close(None).await;
                    }
                }
            },
            _ = ping.tick(), if !we_closed => {
                if socket.send(Message::Ping(Vec::new().into())).await.is_err() {
                    break;
                }
            }
            () = &mut silent => {
                // A peer that stopped answering pings, or one that did not answer our close.
                if we_closed && received.is_none() {
                    received = Some(StreamClose::from_code(Some(CLOSE_NORMAL), None));
                }
                break;
            }
        }
    }
    let close = received.unwrap_or_else(|| {
        if we_closed {
            StreamClose::from_code(Some(CLOSE_NORMAL), None)
        } else {
            StreamClose::from_code(None, None)
        }
    });
    let _ = closed.send(Some(close));
}

/// Opens a stream at `/skakel/v1/streams/{type}` with the token. What the stream is for goes in
/// `query`, as the type defines it. A refusal before the upgrade comes back in the result.
pub(crate) async fn open(
    client: &reqwest::Client,
    server: &Url,
    stream_type: &str,
    query: &[(&str, &str)],
    token: &str,
    timeout: Duration,
) -> Result<OpenResult<StreamConnection>, Error> {
    let url = stream_url(server, stream_type, query)?;
    Ok(
        match ws::open(client, url, token, timeout, MAX_MESSAGE_BYTES).await? {
            Opened::Open(socket) => {
                OpenResult::Opened(StreamConnection::start(stream_type, socket))
            }
            Opened::Refused { status, detail } => {
                OpenResult::Refused(StreamRefusal::from_status(status, detail.as_deref()))
            }
        },
    )
}

fn stream_url(server: &Url, stream_type: &str, query: &[(&str, &str)]) -> Result<Url, Error> {
    let mut url = server
        .join(&format!("{STREAMS_PATH}/{stream_type}"))
        .map_err(Error::from_cause)?;
    if !query.is_empty() {
        url.query_pairs_mut().extend_pairs(query);
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_codes_become_reasons() {
        let cases = [
            (None, StreamCloseReason::ConnectionLost),
            (Some(1006), StreamCloseReason::ConnectionLost),
            (Some(1000), StreamCloseReason::Normal),
            (Some(4001), StreamCloseReason::Revoked),
            (Some(4002), StreamCloseReason::Rotated),
            (Some(4003), StreamCloseReason::ServerStopping),
            (Some(4004), StreamCloseReason::TargetGone),
            (Some(4100), StreamCloseReason::TypeDefined),
            (Some(4999), StreamCloseReason::TypeDefined),
            (Some(1011), StreamCloseReason::Other),
            (Some(5000), StreamCloseReason::Other),
        ];

        for (code, reason) in cases {
            assert_eq!(
                StreamClose::from_code(code, None).reason,
                reason,
                "{code:?}"
            );
        }
    }

    #[test]
    fn a_close_has_fixed_wording() {
        assert_eq!(
            StreamClose::from_code(Some(4001), Some("x".into())).message(),
            "The server revoked this client. Pair with the server again."
        );
        assert_eq!(
            StreamClose::from_code(Some(4100), None).message(),
            "The server closed the stream with code 4100."
        );
        assert_eq!(
            StreamClose::from_code(None, None).message(),
            "The connection to the server was lost."
        );
    }

    #[test]
    fn a_refusal_uses_the_servers_words_or_fixed_ones() {
        let with_detail = StreamRefusal::from_status(409, Some("  bench-2 holds busy. "));
        let without = StreamRefusal::from_status(409, None);

        assert_eq!(with_detail.reason, StreamRefusalReason::InUse);
        assert_eq!(with_detail.message, "bench-2 holds busy.");
        assert_eq!(without.message, "Someone else is using it.");
        assert_eq!(
            StreamRefusal::from_status(500, Some(" ")).message,
            "The server refused the stream (500)."
        );
        assert_eq!(
            StreamRefusal::from_status(401, None).reason,
            StreamRefusalReason::Unauthorized
        );
        assert_eq!(
            StreamRefusal::from_status(400, None).reason,
            StreamRefusalReason::NotAnUpgrade
        );
        assert_eq!(
            StreamRefusal::from_status(404, None).reason,
            StreamRefusalReason::NotFound
        );
        assert_eq!(
            StreamRefusal::from_status(422, None).reason,
            StreamRefusalReason::InvalidQuery
        );
    }

    #[test]
    fn the_stream_url_carries_the_type_and_the_escaped_query() {
        let server = Url::parse("https://10.0.0.5:5240/").unwrap();

        let url = stream_url(&server, "echo", &[("target", "a b&c")]).unwrap();

        assert_eq!(
            url.as_str(),
            "https://10.0.0.5:5240/skakel/v1/streams/echo?target=a+b%26c"
        );
        assert_eq!(stream_url(&server, "echo", &[]).unwrap().query(), None);
    }
}
