//! A stream's data as a byte stream: `AsyncRead` for what the server sends and `AsyncWrite` for what
//! the client sends, so an app can use `tokio::io::copy`, codecs and anything else written for
//! those traits. Control frames are not bytes; they are kept apart and read with
//! [`StreamIo::take_control`].

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use prost::bytes::{Buf, Bytes};
use skakel_proto::v3::{OpenRequest, open_request};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

use crate::streams::{Frame, StreamClose, StreamConnection};

/// The most one write sends as one frame. A longer write is taken in parts.
const MAX_FRAME: usize = 64 * 1024;

/// How many control messages are kept while the app reads data. The oldest goes when it is full.
const MAX_CONTROL: usize = 256;

/// A stream's data as `AsyncRead` and `AsyncWrite`. Made by [`StreamConnection::into_io`].
///
/// Reading ends (end of file) when the server ended the stream, and
/// [`close_info`](Self::close_info) then says how. Shutting down the writing side ends the
/// client's side of the call, as [`StreamConnection::close`] does, and the server then sends what it
/// still has. Dropping it cancels the call and closes the connection.
pub struct StreamIo {
    stream: StreamConnection,
    incoming: mpsc::Receiver<Frame>,
    outgoing: Option<PollSender<OpenRequest>>,
    pending: Bytes,
    controls: VecDeque<Bytes>,
}

impl std::fmt::Debug for StreamIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamIo")
            .field("stream_type", &self.stream.stream_type())
            .finish_non_exhaustive()
    }
}

impl StreamConnection {
    /// The stream as `AsyncRead` and `AsyncWrite` for its data frames. Control frames that come in
    /// while the app reads are kept for [`StreamIo::take_control`]; send them first with
    /// [`send_control`](Self::send_control), which stays on the [`StreamIo`] as
    /// [`StreamIo::send_control`], in order with the data written.
    pub fn into_io(mut self) -> StreamIo {
        let (frames, incoming) = self.take_io_parts();
        StreamIo {
            stream: self,
            incoming,
            outgoing: frames.map(PollSender::new),
            pending: Bytes::new(),
            controls: VecDeque::new(),
        }
    }
}

impl StreamIo {
    /// The control messages that arrived since the last call, in order.
    pub fn take_control(&mut self) -> Vec<Bytes> {
        self.controls.drain(..).collect()
    }

    /// Why the stream ended, once it has.
    pub fn close_info(&self) -> Option<StreamClose> {
        self.stream.close_info()
    }

    /// The stream type.
    pub fn stream_type(&self) -> &str {
        self.stream.stream_type()
    }

    /// Sends one control message, in order with the data written before it.
    pub async fn send_control(&self, message: impl Into<Bytes>) -> Result<(), crate::Error> {
        self.stream.send_control(message).await
    }
}

impl AsyncRead for StreamIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.pending.has_remaining() {
                let take = self.pending.remaining().min(buf.remaining());
                buf.put_slice(&self.pending[..take]);
                self.pending.advance(take);
                return Poll::Ready(Ok(()));
            }
            match self.incoming.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                // The stream ended: end of file.
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Frame::Data(bytes))) => self.pending = bytes,
                Poll::Ready(Some(Frame::Control(bytes))) => {
                    if self.controls.len() >= MAX_CONTROL {
                        self.controls.pop_front();
                    }
                    self.controls.push_back(bytes);
                }
            }
        }
    }
}

/// Sends the start of `data` (at most [`MAX_FRAME`] bytes) as one data frame, once the stream has
/// room, and says how much went. Shared by the byte views of a stream and of a serial connection.
pub(crate) fn poll_write_frame(
    outgoing: &mut Option<PollSender<OpenRequest>>,
    cx: &mut Context<'_>,
    data: &[u8],
) -> Poll<io::Result<usize>> {
    if data.is_empty() {
        return Poll::Ready(Ok(0));
    }
    let Some(outgoing) = outgoing.as_mut() else {
        return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
    };
    match outgoing.poll_reserve(cx) {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Err(_)) => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        Poll::Ready(Ok(())) => {}
    }
    let part = &data[..data.len().min(MAX_FRAME)];
    let sent = outgoing.send_item(OpenRequest {
        frame: Some(open_request::Frame::Data(Bytes::copy_from_slice(part))),
    });
    match sent {
        Ok(()) => Poll::Ready(Ok(part.len())),
        Err(_) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
    }
}

impl AsyncWrite for StreamIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        poll_write_frame(&mut self.outgoing, cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Frames are sent as written; there is nothing held back.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Ends the client's side of the call: the server sends what it still has and ends it.
        if let Some(mut outgoing) = self.outgoing.take() {
            outgoing.close();
        }
        self.stream.end_sending();
        Poll::Ready(Ok(()))
    }
}
