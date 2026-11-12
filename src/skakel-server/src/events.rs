//! What the server tells the app as it happens: pairing requests waiting for a person, how they
//! ended, who the clients are and which certificates are in use.

use tokio::sync::broadcast;

use crate::pairing::{PairingDecision, PairingOverview};
use crate::state::{CertificatesView, ClientView};

/// Something that changed on the server.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ServerEvent {
    /// The requests waiting for a person changed: one arrived, one ended, the budget ran out.
    Pairing(PairingOverview),
    /// A request was approved or refused.
    Decided(PairingDecision),
    /// The list of clients changed.
    Clients(Vec<ClientView>),
    /// The certificate, or the next one being prepared, changed.
    Certificates(CertificatesView),
}

/// What happens on the server, as a stream the app reads with [`recv`](Self::recv). It never runs
/// the app's code, so a slow reader cannot slow the server: it misses the oldest events instead
/// (64 may wait). Get one from [`SkakelServer::subscribe`](crate::SkakelServer::subscribe), and
/// read it on a task of the app's own.
#[derive(Debug)]
pub struct ServerEvents {
    receiver: broadcast::Receiver<ServerEvent>,
}

impl ServerEvents {
    /// The next event, or `None` when the server is gone. An event missed because this was not
    /// read in time is skipped.
    pub async fn recv(&mut self) -> Option<ServerEvent> {
        loop {
            match self.receiver.recv().await {
                Ok(event) => return Some(event),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }

    /// The next event when one is waiting, without waiting for one.
    pub fn try_recv(&mut self) -> Option<ServerEvent> {
        loop {
            match self.receiver.try_recv() {
                Ok(event) => return Some(event),
                Err(broadcast::error::TryRecvError::Lagged(_)) => continue,
                Err(_) => return None,
            }
        }
    }
}

/// Delivers events to everyone who subscribed.
pub(crate) struct Events {
    sender: broadcast::Sender<ServerEvent>,
}

impl Events {
    pub(crate) fn new() -> Self {
        let (sender, _) = broadcast::channel(64);
        Self { sender }
    }

    pub(crate) fn emit(&self, event: ServerEvent) {
        let _ = self.sender.send(event);
    }

    pub(crate) fn subscribe(&self) -> ServerEvents {
        ServerEvents {
            receiver: self.sender.subscribe(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_reader_that_fell_behind_skips_what_it_missed_and_reads_on() {
        let events = Events::new();
        let mut reader = events.subscribe();
        for _ in 0..100 {
            events.emit(ServerEvent::Clients(vec![]));
        }
        events.emit(ServerEvent::Certificates(CertificatesView {
            fingerprint: "AA".into(),
            next_fingerprint: None,
            next_prepared_at: None,
        }));

        let mut last = None;
        while let Some(event) = reader.try_recv() {
            last = Some(event);
        }

        assert!(matches!(last, Some(ServerEvent::Certificates(_))));
    }

    #[tokio::test]
    async fn the_stream_ends_when_the_server_is_gone() {
        let events = Events::new();
        let mut reader = events.subscribe();
        drop(events);

        assert!(reader.recv().await.is_none());
    }
}
