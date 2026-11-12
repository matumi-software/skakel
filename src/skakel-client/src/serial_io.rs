//! A serial connection's data as a byte stream: `AsyncRead` for what the port sends and
//! `AsyncWrite` for what is sent to it, so an app can use `tokio::io::copy` and codecs. The port's
//! settings and lines stay on the [`SerialConnection`] underneath, reached with
//! [`SerialIo::connection`], and work while the data flows.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use prost::bytes::{Buf, Bytes};
use skakel_proto::v3::OpenRequest;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::PollSender;

use crate::serial::SerialConnection;
use crate::stream_io::poll_write_frame;

/// A serial connection's data as `AsyncRead` and `AsyncWrite`. Made by
/// [`SerialConnection::into_io`].
///
/// Reading ends (end of file) when the server ended the stream, and
/// [`SerialConnection::closed`] on [`connection`](Self::connection) then says how. Shutting down
/// the writing side ends the client's side of the call, as [`SerialConnection::close`] does. Data
/// is read through this view only: [`SerialConnection::recv`] on the connection would compete with
/// it for the same bytes, so use one or the other. Control messages (line settings, modem lines,
/// break, purge) are sent with the connection's own methods, in order with the data written.
pub struct SerialIo {
    connection: SerialConnection,
    outgoing: Option<PollSender<OpenRequest>>,
    pending: Bytes,
}

impl std::fmt::Debug for SerialIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SerialIo").finish_non_exhaustive()
    }
}

impl SerialConnection {
    /// The port's data as `AsyncRead` and `AsyncWrite`. The settings, the lines and the events stay
    /// on the connection, which the [`SerialIo`] keeps and lends with [`SerialIo::connection`].
    pub fn into_io(self) -> SerialIo {
        let outgoing = self.outgoing().map(PollSender::new);
        SerialIo {
            connection: self,
            outgoing,
            pending: Bytes::new(),
        }
    }
}

impl SerialIo {
    /// The connection underneath: change the line settings, set the modem lines, watch the port.
    pub fn connection(&self) -> &SerialConnection {
        &self.connection
    }
}

impl AsyncRead for SerialIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.pending.has_remaining() {
                let take = this.pending.remaining().min(buf.remaining());
                buf.put_slice(&this.pending[..take]);
                this.pending.advance(take);
                return Poll::Ready(Ok(()));
            }
            match this.connection.poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                // The stream ended: end of file.
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(bytes)) => this.pending = bytes,
            }
        }
    }
}

impl AsyncWrite for SerialIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        poll_write_frame(&mut self.get_mut().outgoing, cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Frames are sent as written; there is nothing held back.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(mut outgoing) = this.outgoing.take() {
            outgoing.close();
        }
        this.connection.end_sending();
        Poll::Ready(Ok(()))
    }
}
