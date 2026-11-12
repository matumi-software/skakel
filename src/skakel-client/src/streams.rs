//! Data streams: one `StreamService.Open` call that carries one thing, on a connection of its own.
//! Data frames carry the stream's bytes and control frames its control messages, one each, in one
//! order. HTTP/2 flow control is the back pressure: an app that stops reading stops the reads, and
//! the server slows down instead of the client losing data.

use std::sync::Mutex;
use std::time::Duration;

use prost::bytes::Bytes;
use skakel_proto::v2::stream_service_client::StreamServiceClient;
use skakel_proto::v2::{OpenRequest, OpenResponse, StreamOpen, open_request, open_response};
use skakel_wire::{Reason, STREAM_MESSAGE_LIMIT, STREAM_TYPE_DOMAIN_PREFIX};
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Code, Status, Streaming};

use crate::failure::{Error, Failure, FailureKind, bad_answer};
use crate::grpc::{Connection, call_failed, error_info_of, reason_of};
use crate::status::grpc_code;
use skakel_wire::GrpcCode;

/// How long a close waits for the server to end the call.
const CLOSE_TIMEOUT: Duration = Duration::from_millis(2500);

/// How many frames wait to go out, and how many wait for the app to read them.
const FRAMES: usize = 16;

/// A frame of an open stream.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Frame {
    /// Data, the stream's own bytes.
    Data(Bytes),
    /// One control message, encoded as the stream type defines.
    Control(Bytes),
}

/// Why a stream ended, by the status the call ended with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamCloseReason {
    /// `OK`: closed normally.
    Normal,
    /// `REVOKED`: the client was revoked.
    Revoked,
    /// `ROTATED`: the client's secret was rotated.
    Rotated,
    /// `STOPPING`: the server is stopping, or no longer serves this type.
    ServerStopping,
    /// `TARGET_GONE`: the target went away, such as a device that was unplugged.
    TargetGone,
    /// `ABORTED` for a reason the stream type defines. [`StreamClose::type_reason`] says which.
    TypeDefined,
    /// The connection dropped or stopped answering pings: a status with no Skakel reason.
    ConnectionLost,
    /// Any other status.
    Other,
}

/// How a stream ended.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StreamClose {
    /// The status as a reason a client acts on.
    pub reason: StreamCloseReason,
    /// The status code the call ended with.
    pub code: GrpcCode,
    /// For [`StreamCloseReason::TypeDefined`], the reason the stream type gave, such as
    /// `PORT_FAULT`.
    pub type_reason: Option<String>,
    /// The server's words, for the log only.
    pub description: Option<String>,
}

impl StreamClose {
    /// A stream that ended with `OK`.
    pub(crate) fn normal() -> Self {
        Self {
            reason: StreamCloseReason::Normal,
            code: GrpcCode::Ok,
            type_reason: None,
            description: None,
        }
    }

    /// A stream whose connection was lost.
    pub(crate) fn connection_lost() -> Self {
        Self {
            reason: StreamCloseReason::ConnectionLost,
            code: GrpcCode::Unavailable,
            type_reason: None,
            description: None,
        }
    }

    /// The close for the status a stream ended with.
    pub(crate) fn from_status(status: &Status) -> Self {
        let info = error_info_of(status);
        let mut type_reason = None;
        let reason = match (status.code(), reason_of(status)) {
            (Code::Ok, _) => StreamCloseReason::Normal,
            (_, Some(Reason::Revoked)) => StreamCloseReason::Revoked,
            (_, Some(Reason::Rotated)) => StreamCloseReason::Rotated,
            (_, Some(Reason::Stopping)) => StreamCloseReason::ServerStopping,
            (_, Some(Reason::TargetGone)) => StreamCloseReason::TargetGone,
            (Code::Aborted, None)
                if info
                    .as_ref()
                    .is_some_and(|(domain, _)| domain.starts_with(STREAM_TYPE_DOMAIN_PREFIX)) =>
            {
                type_reason = info.map(|(_, reason)| reason);
                StreamCloseReason::TypeDefined
            }
            (Code::Unavailable | Code::Cancelled | Code::Unknown, None) if info.is_none() => {
                StreamCloseReason::ConnectionLost
            }
            _ => StreamCloseReason::Other,
        };
        Self {
            reason,
            code: grpc_code(status.code()),
            type_reason,
            description: Some(status.message().to_owned()).filter(|m| !m.is_empty()),
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
            StreamCloseReason::TypeDefined => format!(
                "The server ended the stream: {}.",
                self.type_reason.as_deref().unwrap_or("?")
            ),
            StreamCloseReason::Other => {
                format!("The server ended the stream with {:?}.", self.code)
            }
        }
    }
}

/// Why the server refused to open a stream, by the reason it gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamRefusalReason {
    /// `TOKEN_REFUSED`: no token, an expired one, or one from an older generation.
    Unauthorized,
    /// `NO_SUCH_TYPE`: the server does not offer this stream type.
    NoSuchType,
    /// `NO_SUCH_TARGET`: the server has no such target; it may come back later.
    NoSuchTarget,
    /// `IN_USE`: the target is in use. [`StreamRefusal::message`] names who holds it, when the app
    /// allows that.
    InUse,
    /// `BAD_TARGET`: the target is not what the type expects.
    BadTarget,
    /// `BAD_OPEN` or `BAD_FRAME`: the client opened the stream wrong, which is a bug.
    BadOpen,
    /// Any other reason.
    Other,
}

/// The server refused to open a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StreamRefusal {
    /// The status code.
    pub code: GrpcCode,
    /// The reason.
    pub reason: StreamRefusalReason,
    /// The server's words for a person, or fixed wording when it sent none.
    pub message: String,
}

impl StreamRefusal {
    /// The refusal for the status the call ended with before `opened`.
    pub(crate) fn from_status(status: &Status) -> Self {
        let reason = match reason_of(status) {
            Some(Reason::TokenRefused) => StreamRefusalReason::Unauthorized,
            Some(Reason::NoSuchType) => StreamRefusalReason::NoSuchType,
            Some(Reason::NoSuchTarget) => StreamRefusalReason::NoSuchTarget,
            Some(Reason::InUse) => StreamRefusalReason::InUse,
            Some(Reason::BadTarget) => StreamRefusalReason::BadTarget,
            Some(Reason::BadOpen | Reason::BadFrame) => StreamRefusalReason::BadOpen,
            _ => StreamRefusalReason::Other,
        };
        let message = match status.message().trim() {
            "" => match reason {
                StreamRefusalReason::Unauthorized => {
                    Failure::of(FailureKind::ClientUnknown).message().to_owned()
                }
                StreamRefusalReason::NoSuchType => {
                    "The server does not offer this kind of stream.".to_owned()
                }
                StreamRefusalReason::NoSuchTarget => "The server has no such target.".to_owned(),
                StreamRefusalReason::InUse => "Someone else is using it.".to_owned(),
                StreamRefusalReason::BadTarget => {
                    "The server did not understand what the stream was asked for.".to_owned()
                }
                _ => format!("The server refused the stream ({:?}).", status.code()),
            },
            words => words.to_owned(),
        };
        Self {
            code: grpc_code(status.code()),
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
    /// The server refused, with its reason and its words for it.
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

/// An open stream, on a connection of its own. Dropping it cancels the call and closes the
/// connection; use [`close`](Self::close) to end it properly.
pub struct StreamConnection {
    stream_type: String,
    frames: Mutex<Option<mpsc::Sender<OpenRequest>>>,
    incoming: tokio::sync::Mutex<mpsc::Receiver<Frame>>,
    closed: watch::Receiver<Option<StreamClose>>,
    task: tokio::task::AbortHandle,
    _connection: Connection,
}

impl std::fmt::Debug for StreamConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamConnection")
            .field("stream_type", &self.stream_type)
            .finish_non_exhaustive()
    }
}

impl Drop for StreamConnection {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

impl StreamConnection {
    fn start(
        stream_type: &str,
        connection: Connection,
        frames: mpsc::Sender<OpenRequest>,
        answers: Streaming<OpenResponse>,
    ) -> Self {
        let (incoming_tx, incoming) = mpsc::channel(FRAMES);
        let (closed_tx, closed) = watch::channel(None);
        let task = tokio::spawn(read(answers, incoming_tx, closed_tx));
        Self {
            stream_type: stream_type.to_owned(),
            frames: Mutex::new(Some(frames)),
            incoming: tokio::sync::Mutex::new(incoming),
            closed,
            task: task.abort_handle(),
            _connection: connection,
        }
    }

    /// The stream type.
    pub fn stream_type(&self) -> &str {
        &self.stream_type
    }

    /// Sends data. Frames go out in the order they were sent, control messages among them, so a
    /// control message takes effect between the bytes sent before it and the bytes sent after it.
    /// It waits while the server takes the frames sent before.
    pub async fn send_data(&self, data: impl Into<Bytes>) -> Result<(), Error> {
        self.send(open_request::Frame::Data(data.into())).await
    }

    /// Sends one control message, encoded as the stream type defines.
    pub async fn send_control(&self, message: impl Into<Bytes>) -> Result<(), Error> {
        self.send(open_request::Frame::Control(message.into()))
            .await
    }

    async fn send(&self, frame: open_request::Frame) -> Result<(), Error> {
        let frames = lock(&self.frames).clone();
        let Some(frames) = frames else {
            return Err(Error::of(FailureKind::ConnectionLost));
        };
        frames
            .send(OpenRequest { frame: Some(frame) })
            .await
            .map_err(|_| Error::of(FailureKind::ConnectionLost))
    }

    /// The next frame, or `None` once the stream has ended and everything was read. One task at a
    /// time reads.
    pub async fn recv(&self) -> Option<Frame> {
        self.incoming.lock().await.recv().await
    }

    /// Why the stream ended, once it has. `None` while it is open.
    pub fn close_info(&self) -> Option<StreamClose> {
        self.closed.borrow().clone()
    }

    /// Waits until the stream has ended, and says how. The server's status comes after the frames
    /// it sent on the call (HTTP/2 delivers them in order), so while the app leaves frames
    /// unread and the buffer is full, this does not return: read them, or [`close`](Self::close).
    pub async fn closed(&self) -> StreamClose {
        let mut closed = self.closed.clone();
        match closed.wait_for(Option::is_some).await {
            Ok(close) => close.clone().unwrap_or_else(StreamClose::connection_lost),
            Err(_) => StreamClose::connection_lost(),
        }
    }

    /// The parts a byte-stream view needs: a sender for what goes out and the receiver of what
    /// comes in, which this connection then no longer reads.
    pub(crate) fn take_io_parts(
        &mut self,
    ) -> (Option<mpsc::Sender<OpenRequest>>, mpsc::Receiver<Frame>) {
        let incoming = std::mem::replace(self.incoming.get_mut(), mpsc::channel(1).1);
        let frames = lock(&self.frames).clone();
        (frames, incoming)
    }

    /// A sender for what goes out, for a byte-stream view that is not this connection itself.
    pub(crate) fn outgoing(&self) -> Option<mpsc::Sender<OpenRequest>> {
        lock(&self.frames).clone()
    }

    /// Ends the client's side of the call without waiting for the server.
    pub(crate) fn end_sending(&self) {
        lock(&self.frames).take();
    }

    /// Ends the client's side of the stream and waits briefly for the server to send what it still
    /// has and end the call. Never fails for a stream that is already gone.
    pub async fn close(&self) {
        lock(&self.frames).take();
        let _ = tokio::time::timeout(CLOSE_TIMEOUT, self.closed()).await;
    }
}

/// Reads the server's frames until the call ends, then says how. A frame is read only when the app
/// has room for it.
async fn read(
    mut answers: Streaming<OpenResponse>,
    incoming: mpsc::Sender<Frame>,
    closed: watch::Sender<Option<StreamClose>>,
) {
    let close = loop {
        let Ok(room) = incoming.reserve().await else {
            // Nobody reads any more; the stream is dropped with its connection.
            return;
        };
        match answers.message().await {
            Ok(Some(OpenResponse {
                frame: Some(open_response::Frame::Data(data)),
            })) => room.send(Frame::Data(data)),
            Ok(Some(OpenResponse {
                frame: Some(open_response::Frame::Control(control)),
            })) => room.send(Frame::Control(control)),
            // A second `opened`, or a kind this end does not know.
            Ok(Some(_)) => {}
            Ok(None) => break StreamClose::normal(),
            // tonic reports a frame over the limit as OUT_OF_RANGE; the protocol says
            // RESOURCE_EXHAUSTED.
            Err(status) if status.code() == Code::OutOfRange => {
                break StreamClose::from_status(&Status::resource_exhausted(status.message()));
            }
            Err(status) => break StreamClose::from_status(&status),
        }
    };
    let _ = closed.send(Some(close));
}

/// A request that carries `token` as its bearer token, marked sensitive so it stays out of logs.
/// A token that is not a header value never gets here: the token client refuses it when it is
/// issued.
pub(crate) fn with_token<T>(message: T, token: &str) -> tonic::Request<T> {
    let mut request = tonic::Request::new(message);
    if let Ok(mut value) = format!("Bearer {token}").parse::<tonic::metadata::AsciiMetadataValue>()
    {
        value.set_sensitive(true);
        request.metadata_mut().insert("authorization", value);
    }
    request
}

/// Opens a stream of `stream_type` for `target` on `connection` with `token`, and waits up to
/// `timeout` for `opened`. A refusal before it comes back in the result.
pub(crate) async fn open(
    connection: Connection,
    stream_type: &str,
    target: &[u8],
    token: &str,
    timeout: Duration,
) -> Result<OpenResult<StreamConnection>, Error> {
    let (frames, frames_rx) = mpsc::channel(FRAMES);
    frames
        .try_send(OpenRequest {
            frame: Some(open_request::Frame::Open(StreamOpen {
                stream_type: stream_type.to_owned(),
                target: Bytes::copy_from_slice(target),
            })),
        })
        .expect("a new channel has room");
    let mut client = StreamServiceClient::new(connection.service())
        .max_decoding_message_size(STREAM_MESSAGE_LIMIT)
        .max_encoding_message_size(STREAM_MESSAGE_LIMIT);
    let request = with_token(ReceiverStream::new(frames_rx), token);
    let opening = async {
        let mut answers = client.open(request).await?.into_inner();
        match answers.message().await? {
            Some(OpenResponse {
                frame: Some(open_response::Frame::Opened(_)),
            }) => Ok(Ok(answers)),
            _ => Ok(Err(())),
        }
    };
    let opened: Result<Result<Streaming<OpenResponse>, ()>, Status> =
        tokio::time::timeout(timeout, opening)
            .await
            .map_err(Error::from_cause)?;
    match opened {
        Ok(Ok(answers)) => Ok(OpenResult::Opened(StreamConnection::start(
            stream_type,
            connection,
            frames,
            answers,
        ))),
        Ok(Err(())) => Err(bad_answer("The stream's first frame was not opened.")),
        Err(status) if reason_of(&status).is_some() => {
            Ok(OpenResult::Refused(StreamRefusal::from_status(&status)))
        }
        Err(status) => Err(call_failed(status)),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use tonic_types::{ErrorDetails, StatusExt};

    use super::*;

    fn with(code: Code, reason: &str, domain: &str, message: &str) -> Status {
        Status::with_error_details(
            code,
            message,
            ErrorDetails::with_error_info(reason, domain, HashMap::new()),
        )
    }

    #[test]
    fn statuses_become_close_reasons() {
        let cases = [
            (Status::ok(""), StreamCloseReason::Normal),
            (
                with(Code::Unauthenticated, "REVOKED", "skakel", ""),
                StreamCloseReason::Revoked,
            ),
            (
                with(Code::Unauthenticated, "ROTATED", "skakel", ""),
                StreamCloseReason::Rotated,
            ),
            (
                with(Code::Unavailable, "STOPPING", "skakel", ""),
                StreamCloseReason::ServerStopping,
            ),
            (
                with(Code::NotFound, "TARGET_GONE", "skakel", ""),
                StreamCloseReason::TargetGone,
            ),
            (
                with(Code::Aborted, "PORT_FAULT", "skakel.streams.serial", ""),
                StreamCloseReason::TypeDefined,
            ),
            (
                Status::unavailable("gone"),
                StreamCloseReason::ConnectionLost,
            ),
            (Status::cancelled(""), StreamCloseReason::ConnectionLost),
            (
                with(Code::Aborted, "X", "someone.else", ""),
                StreamCloseReason::Other,
            ),
            (Status::internal(""), StreamCloseReason::Other),
        ];

        for (status, reason) in cases {
            assert_eq!(
                StreamClose::from_status(&status).reason,
                reason,
                "{status:?}"
            );
        }
    }

    #[test]
    fn a_close_has_fixed_wording_and_keeps_the_types_reason() {
        let fault = StreamClose::from_status(&with(
            Code::Aborted,
            "PORT_FAULT",
            "skakel.streams.serial",
            "The port reported a fault.",
        ));

        assert_eq!(fault.type_reason.as_deref(), Some("PORT_FAULT"));
        assert_eq!(fault.message(), "The server ended the stream: PORT_FAULT.");
        assert_eq!(
            fault.description.as_deref(),
            Some("The port reported a fault.")
        );
        assert_eq!(
            StreamClose::from_status(&with(Code::Unauthenticated, "REVOKED", "skakel", "x"))
                .message(),
            "The server revoked this client. Pair with the server again."
        );
        assert_eq!(
            StreamClose::connection_lost().message(),
            "The connection to the server was lost."
        );
    }

    #[test]
    fn a_refusal_uses_the_servers_words_or_fixed_ones() {
        let with_words = StreamRefusal::from_status(&with(
            Code::FailedPrecondition,
            "IN_USE",
            "skakel",
            "  bench-2 holds busy. ",
        ));
        let without =
            StreamRefusal::from_status(&with(Code::FailedPrecondition, "IN_USE", "skakel", ""));

        assert_eq!(with_words.reason, StreamRefusalReason::InUse);
        assert_eq!(with_words.code, GrpcCode::FailedPrecondition);
        assert_eq!(with_words.message, "bench-2 holds busy.");
        assert_eq!(without.message, "Someone else is using it.");
        for (reason, expected) in [
            ("TOKEN_REFUSED", StreamRefusalReason::Unauthorized),
            ("NO_SUCH_TYPE", StreamRefusalReason::NoSuchType),
            ("NO_SUCH_TARGET", StreamRefusalReason::NoSuchTarget),
            ("BAD_TARGET", StreamRefusalReason::BadTarget),
            ("BAD_OPEN", StreamRefusalReason::BadOpen),
            ("BAD_FRAME", StreamRefusalReason::BadOpen),
            ("STOPPING", StreamRefusalReason::Other),
        ] {
            assert_eq!(
                StreamRefusal::from_status(&with(Code::NotFound, reason, "skakel", "")).reason,
                expected,
                "{reason}"
            );
        }
    }
}
