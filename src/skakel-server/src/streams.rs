//! Data streams, `skakel.v2.StreamService.Open`: one call that carries one thing.
//!
//! The app registers a handler per stream type. The handler looks at the request (the client, the
//! target) and either refuses it, with words a person can read, or accepts it and gets a
//! [`StreamSession`] to read and write frames on. The server ends the stream with `OK` when the
//! handler returns, with the handler's own status when it ends it otherwise, and with `REVOKED`,
//! `ROTATED` or `STOPPING` when the client is revoked, its secret rotated or the server stops.
//!
//! HTTP/2's flow control carries the back pressure: frames wait in small queues between the call and
//! the handler, and while a queue is full the server stops reading the call, or stops sending on it,
//! so a slow end slows the other instead of losing bytes.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use axum::extract::ConnectInfo;
use prost::bytes::Bytes;
use skakel_proto::v2::stream_service_server::StreamService;
use skakel_proto::v2::{OpenRequest, OpenResponse, StreamOpened, open_request, open_response};
use skakel_protocol::{
    OPEN_TIMEOUT, Reason, STREAM_MESSAGE_LIMIT, is_reason, is_stream_type, stream_type_domain,
};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_stream::Stream;
use tonic::{Code, Request, Response, Status, Streaming};
use tonic_types::{ErrorDetails, StatusExt};

use crate::control::principal_of;
use crate::error::ServerError;
use crate::grpc::{ending, read_failed, refusal};
use crate::server::Shared;
use crate::sessions::SessionGuard;

/// How long a handler has to return once its stream is over, before it is stopped.
const RETURN_TIMEOUT: Duration = Duration::from_secs(5);
/// Frames waiting between the call and the handler, either way.
const QUEUE: usize = 16;

/// A boxed future, the way a handler returns an async result.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A frame on a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamMessage {
    /// The stream's data, bytes the stream type defines.
    Data(Bytes),
    /// One control message, encoded as the stream type defines.
    Control(Bytes),
}

/// What a handler is asked to open.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct StreamRequest {
    /// The stream type, from the `open` frame.
    pub stream_type: String,
    /// The id of the client that opens it.
    pub client_id: String,
    /// The name that client was registered under.
    pub client_name: String,
    /// The address the call came from.
    pub remote: IpAddr,
    /// What the stream is for, a message the stream type defines, encoded. Empty for a type that
    /// needs nothing.
    pub target: Bytes,
}

type Run = Box<dyn FnOnce(StreamSession) -> BoxFuture<'static, ()> + Send>;

/// What [`StreamOpen::accept`] makes: the work to run on an accepted stream. An app does not build
/// one itself, so it can only accept a stream through [`StreamOpen::accept`].
///
/// ```compile_fail
/// let _ = skakel_server::Accepted(Box::new(|_| Box::pin(async {})));
/// ```
pub struct Accepted(Run);

/// A handler's answer to a request to open a stream. Each refusal ends the call before `opened`,
/// with the words for a person.
#[non_exhaustive]
pub enum StreamOpen {
    /// Accept: the server sends `opened` and runs this with the session. Made by
    /// [`StreamOpen::accept`].
    Accept(Accepted),
    /// `NO_SUCH_TARGET`: there is no such target (a port, a device).
    NotFound(String),
    /// `IN_USE`: the target is in use; the words may say who holds it.
    InUse(String),
    /// `BAD_TARGET`: the target is not what the type expects.
    BadTarget(String),
}

impl StreamOpen {
    /// Accepts the stream and runs `run` on it. When `run` returns, the server ends the stream
    /// with `OK`, after the frames sent before.
    pub fn accept<F, Fut>(run: F) -> Self
    where
        F: FnOnce(StreamSession) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        Self::Accept(Accepted(Box::new(move |session| Box::pin(run(session)))))
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum End {
    Normal,
    TargetGone(String),
    Aborted { reason: String, message: String },
}

/// How a handler ends its stream: normally, because the target went away, or for a reason the
/// stream type defines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamEnd(End);

impl StreamEnd {
    /// `OK`: closed normally.
    pub fn normal() -> Self {
        Self(End::Normal)
    }

    /// `TARGET_GONE`: the target went away (unplugged, removed). The message is for a person.
    pub fn target_gone(message: impl Into<String>) -> Self {
        Self(End::TargetGone(message.into()))
    }

    /// `ABORTED`, for a reason the stream type defines, in the domain `skakel.streams.<type>`. The
    /// reason is upper case letters, digits and `_`, starting with a letter, at most 63
    /// characters, such as `PORT_FAULT`; the message is for a person.
    pub fn aborted(
        reason: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<Self, ServerError> {
        let reason = reason.into();
        if !is_reason(&reason) {
            return Err(ServerError::Invalid(format!(
                "The reason '{reason}' must be upper case letters, digits and _, start with a letter and be at most 63 characters."
            )));
        }
        Ok(Self(End::Aborted {
            reason,
            message: message.into(),
        }))
    }

    /// The status it ends the call with, or `None` for `OK`.
    fn status(&self, stream_type: &str) -> Option<Status> {
        match &self.0 {
            End::Normal => None,
            End::TargetGone(message) => Some(refusal(Reason::TargetGone, message.clone())),
            End::Aborted { reason, message } => Some(Status::with_error_details(
                Code::Aborted,
                message.clone(),
                ErrorDetails::with_error_info(
                    reason.clone(),
                    stream_type_domain(stream_type),
                    std::collections::HashMap::new(),
                ),
            )),
        }
    }
}

enum Outgoing {
    Message(StreamMessage),
    End(StreamEnd),
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

    /// Sends data.
    pub async fn send_data(&self, data: impl Into<Bytes>) -> Result<(), StreamClosed> {
        self.send(StreamMessage::Data(data.into())).await
    }

    /// Sends one control message, encoded.
    pub async fn send_control(&self, message: impl Into<Bytes>) -> Result<(), StreamClosed> {
        self.send(StreamMessage::Control(message.into())).await
    }

    /// Ends the stream. Frames sent before it are delivered first.
    pub async fn end(&self, end: StreamEnd) {
        let _ = self.out.send(Outgoing::End(end)).await;
    }

    /// Ends the stream normally, with `OK`, after the frames sent before.
    pub async fn close(&self) {
        self.end(StreamEnd::normal()).await;
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
    /// The next frame, or `None` once the stream is over: the client ended its side or cancelled
    /// the call, the server ended it (revoked, rotated, stopping) or the connection dropped.
    /// Frames that arrived before the end are still returned first.
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

    /// Sends data.
    pub async fn send_data(&self, data: impl Into<Bytes>) -> Result<(), StreamClosed> {
        self.writer.send_data(data).await
    }

    /// Sends one control message, encoded.
    pub async fn send_control(&self, message: impl Into<Bytes>) -> Result<(), StreamClosed> {
        self.writer.send_control(message).await
    }

    /// Ends the stream; see [`StreamWriter::end`].
    pub async fn end(&self, end: StreamEnd) {
        self.writer.end(end).await;
    }

    /// Ends the stream normally; see [`StreamWriter::close`].
    pub async fn close(&self) {
        self.writer.close().await;
    }

    /// Resolves when the stream is over or ending, whoever began it.
    pub async fn ended(&self) {
        let mut ending = self.ending.clone();
        let _ = ending.wait_for(|over| *over).await;
    }
}

/// The stream service.
pub(crate) struct Streams {
    pub shared: Arc<Shared>,
}

/// What the server sends on a stream: the frames in order, ended by the handler's status, or at once
/// by the status of a revoke, a rotation or a stop.
pub(crate) struct Outbound {
    queue: mpsc::Receiver<Result<OpenResponse, Status>>,
    urgent: Option<oneshot::Receiver<Status>>,
    done: bool,
}

impl Stream for Outbound {
    type Item = Result<OpenResponse, Status>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.done {
            return Poll::Ready(None);
        }
        if let Some(urgent) = self.urgent.as_mut()
            && let Poll::Ready(status) = Pin::new(urgent).poll(cx)
        {
            self.urgent = None;
            if let Ok(status) = status {
                self.done = true;
                return Poll::Ready(Some(Err(status)));
            }
        }
        let item = ready!(self.queue.poll_recv(cx));
        if !matches!(item, Some(Ok(_))) {
            self.done = true;
        }
        Poll::Ready(item)
    }
}

fn bad_open(message: &str) -> Status {
    refusal(Reason::BadOpen, message)
}

#[tonic::async_trait]
impl StreamService for Streams {
    type OpenStream = Outbound;

    async fn open(
        &self,
        request: Request<Streaming<OpenRequest>>,
    ) -> Result<Response<Self::OpenStream>, Status> {
        let principal = principal_of(&request)?;
        let remote = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |info| info.0.ip());
        let mut inbound = request.into_inner();
        let open = match tokio::time::timeout(OPEN_TIMEOUT, inbound.message()).await {
            Err(_) => {
                return Err(bad_open(
                    "No open frame came within 15 seconds of the call starting.",
                ));
            }
            Ok(Err(status)) => return Err(read_failed(status)),
            Ok(Ok(Some(OpenRequest {
                frame: Some(open_request::Frame::Open(open)),
            }))) => open,
            Ok(Ok(_)) => return Err(bad_open("A stream's first frame is open.")),
        };
        if !is_stream_type(&open.stream_type) {
            return Err(bad_open("A stream type is one or more of a-z, 0-9 and -."));
        }
        let Some(handler) = self.shared.streams.get(&open.stream_type).cloned() else {
            return Err(refusal(
                Reason::NoSuchType,
                format!("This server has no stream type '{}'.", open.stream_type),
            ));
        };
        let client_name = self
            .shared
            .state
            .find(&principal.client_id)
            .map_or_else(|| principal.client_id.clone(), |client| client.name);
        let request = StreamRequest {
            stream_type: open.stream_type,
            client_id: principal.client_id.clone(),
            client_name,
            remote,
            target: open.target,
        };

        // The client sends nothing more until the server answers; anything it does is a bug.
        let deciding = handler(request.clone());
        tokio::pin!(deciding);
        let mut half_closed = false;
        let decision = loop {
            tokio::select! {
                decision = &mut deciding => break decision,
                frame = inbound.message(), if !half_closed => match frame {
                    Ok(Some(_)) => {
                        return Err(refusal(
                            Reason::BadFrame,
                            "The client sent a frame before the server answered its open.",
                        ));
                    }
                    Ok(None) => half_closed = true,
                    Err(status) => return Err(read_failed(status)),
                },
            }
        };
        let run = match decision {
            StreamOpen::NotFound(message) => return Err(refusal(Reason::NoSuchTarget, message)),
            StreamOpen::InUse(message) => return Err(refusal(Reason::InUse, message)),
            StreamOpen::BadTarget(message) => return Err(refusal(Reason::BadTarget, message)),
            StreamOpen::Accept(Accepted(run)) => run,
        };

        let (guard, ended) = self
            .shared
            .sessions
            .add_call(&principal.client_id, principal.generation);
        let (queue_tx, queue_rx) = mpsc::channel(QUEUE);
        let (urgent_tx, urgent_rx) = oneshot::channel();
        let opened = OpenResponse {
            frame: Some(open_response::Frame::Opened(StreamOpened {})),
        };
        queue_tx.try_send(Ok(opened)).expect("a new queue has room");
        let (in_tx, in_rx) = mpsc::channel(QUEUE);
        let (writer_tx, writer_rx) = mpsc::channel(QUEUE);
        let (ending_tx, ending_rx) = watch::channel(false);
        let session = StreamSession {
            stream_type: request.stream_type.clone(),
            client_id: request.client_id,
            client_name: request.client_name,
            incoming: in_rx,
            writer: StreamWriter { out: writer_tx },
            ending: ending_rx,
        };
        let pump = Pump {
            stream_type: request.stream_type,
            inbound,
            reading: !half_closed,
            to_handler: (!half_closed).then_some(in_tx),
            from_handler: writer_rx,
            queue: queue_tx,
            urgent: Some(urgent_tx),
            ended,
            ending: ending_tx,
        };
        tokio::spawn(serve(pump, run(session), guard));
        Ok(Response::new(Outbound {
            queue: queue_rx,
            urgent: Some(urgent_rx),
            done: false,
        }))
    }
}

/// Runs an accepted stream: the handler on a task of its own, the frames here.
async fn serve(pump: Pump, handler: BoxFuture<'static, ()>, guard: SessionGuard) {
    let mut handler = tokio::spawn(handler);
    pump.run().await;
    if tokio::time::timeout(RETURN_TIMEOUT, &mut handler)
        .await
        .is_err()
    {
        handler.abort();
    }
    drop(guard);
}

/// Moves frames between the call and the handler until the stream is over.
struct Pump {
    stream_type: String,
    inbound: Streaming<OpenRequest>,
    reading: bool,
    to_handler: Option<mpsc::Sender<StreamMessage>>,
    from_handler: mpsc::Receiver<Outgoing>,
    queue: mpsc::Sender<Result<OpenResponse, Status>>,
    urgent: Option<oneshot::Sender<Status>>,
    ended: oneshot::Receiver<Reason>,
    ending: watch::Sender<bool>,
}

/// Room for one frame on its way to the handler; never ready once the handler is not reading.
async fn room(
    to_handler: &Option<mpsc::Sender<StreamMessage>>,
) -> Option<mpsc::Permit<'_, StreamMessage>> {
    match to_handler {
        Some(sender) => sender.reserve().await.ok(),
        None => std::future::pending().await,
    }
}

fn response(message: StreamMessage) -> OpenResponse {
    OpenResponse {
        frame: Some(match message {
            StreamMessage::Data(data) => open_response::Frame::Data(data),
            StreamMessage::Control(control) => open_response::Frame::Control(control),
        }),
    }
}

/// The frame for the client, or the status that ends the stream when the frame is over the limit.
/// tonic would end the call with `OUT_OF_RANGE`; the protocol says `RESOURCE_EXHAUSTED`, as gRPC's
/// other implementations do, so the limit is checked here, before tonic sees the frame.
fn to_client(message: StreamMessage) -> Result<OpenResponse, Status> {
    let response = response(message);
    let size = prost::Message::encoded_len(&response);
    if size > STREAM_MESSAGE_LIMIT {
        return Err(Status::resource_exhausted(format!(
            "The server's frame of {size} bytes is over the limit of {STREAM_MESSAGE_LIMIT} bytes."
        )));
    }
    Ok(response)
}

impl Pump {
    /// Ends the call at once with `status`, before anything still queued.
    fn end_now(&mut self, status: Status) {
        if let Some(urgent) = self.urgent.take() {
            let _ = urgent.send(status);
        }
    }

    async fn run(mut self) {
        // A frame read from one side and waiting for room on the other.
        let mut for_handler: Option<StreamMessage> = None;
        let mut for_client: Option<Result<OpenResponse, Status>> = None;
        loop {
            let step = tokio::select! {
                biased;
                reason = &mut self.ended => Step::EndNow(ending(reason.unwrap_or(Reason::Stopping))),
                permit = self.queue.reserve(), if for_client.is_some() => match permit {
                    Ok(permit) => {
                        let item = for_client.take().expect("checked by the guard");
                        let last = item.is_err();
                        permit.send(item);
                        if last { Step::Stop } else { Step::Go }
                    }
                    Err(_) => Step::Stop,
                },
                outgoing = self.from_handler.recv(), if for_client.is_none() => match outgoing {
                    Some(Outgoing::Message(message)) => {
                        for_client = Some(to_client(message));
                        Step::Go
                    }
                    Some(Outgoing::End(end)) => match end.status(&self.stream_type) {
                        Some(status) => {
                            for_client = Some(Err(status));
                            Step::Go
                        }
                        None => Step::Stop,
                    },
                    // The handler returned and nobody else holds a writer: closed normally.
                    None => Step::Stop,
                },
                permit = room(&self.to_handler), if for_handler.is_some() => {
                    match permit {
                        Some(permit) => permit.send(for_handler.take().expect("checked by the guard")),
                        // The handler stopped reading; what the client sends is dropped.
                        None => for_handler = None,
                    }
                    Step::Go
                }
                frame = self.inbound.message(), if self.reading && for_handler.is_none() => match frame {
                    Ok(Some(OpenRequest { frame: Some(open_request::Frame::Data(data)) })) => {
                        if self.to_handler.is_some() {
                            for_handler = Some(StreamMessage::Data(data));
                        }
                        Step::Go
                    }
                    Ok(Some(OpenRequest { frame: Some(open_request::Frame::Control(control)) })) => {
                        if self.to_handler.is_some() {
                            for_handler = Some(StreamMessage::Control(control));
                        }
                        Step::Go
                    }
                    Ok(Some(OpenRequest { frame: Some(open_request::Frame::Open(_)) })) => Step::EndNow(
                        refusal(Reason::BadFrame, "A stream has one open frame, the first."),
                    ),
                    Ok(Some(OpenRequest { frame: None })) => Step::EndNow(refusal(
                        Reason::BadFrame,
                        "A frame carries open, data or control.",
                    )),
                    // The client ended its side: the handler reads the end, sends what it still
                    // has and returns.
                    Ok(None) => Step::HalfClosed,
                    // A frame over the limit, which ends the call as gRPC does, or a client
                    // that cancelled or is gone, which hears nothing more anyway.
                    Err(status) => Step::EndNow(read_failed(status)),
                },
                () = self.queue.closed() => Step::Stop,
            };
            match step {
                Step::Go => {}
                Step::Stop => break,
                Step::EndNow(status) => {
                    self.end_now(status);
                    break;
                }
                Step::HalfClosed => {
                    self.reading = false;
                    self.to_handler = None;
                }
            }
        }
        self.ending.send_replace(true);
        // Dropping the queue ends the call: with OK once what is queued has gone, unless it was
        // ended with a status above.
    }
}

/// What the pump does after one turn.
enum Step {
    Go,
    Stop,
    EndNow(Status),
    HalfClosed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stream_type_aborts_in_its_own_domain_with_a_reason_it_names() {
        let end = StreamEnd::aborted("PORT_FAULT", "The port reported a fault.").unwrap();

        let status = end.status("serial").unwrap();

        assert_eq!(status.code(), Code::Aborted);
        assert_eq!(status.message(), "The port reported a fault.");
        let info = status.get_details_error_info().unwrap();
        assert_eq!(info.domain, "skakel.streams.serial");
        assert_eq!(info.reason, "PORT_FAULT");
    }

    #[test]
    fn a_reason_that_breaks_the_rule_is_refused() {
        assert!(StreamEnd::aborted("port fault", "").is_err());
        assert!(StreamEnd::aborted("", "").is_err());
    }

    #[test]
    fn a_normal_end_is_ok_and_a_target_that_went_away_is_target_gone() {
        assert!(StreamEnd::normal().status("echo").is_none());
        let gone = StreamEnd::target_gone("unplugged").status("echo").unwrap();
        assert_eq!(gone.code(), Code::NotFound);
        assert_eq!(gone.get_details_error_info().unwrap().reason, "TARGET_GONE");
    }
}
