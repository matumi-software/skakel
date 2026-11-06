//! The live hub connections and streams, and ending them when their client is revoked, its
//! secret rotated or the server stops.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use serde_json::Value;
use skakel_protocol::{
    CLOSING_REVOKED, CLOSING_ROTATED, CLOSING_STOPPING, HUB_CERTIFICATES, SkakelCertificates,
};
use tokio::sync::mpsc;

use crate::state::ServerState;

/// What the server tells a hub connection to do.
pub(crate) enum HubOut {
    /// Send the client an invocation.
    Invoke {
        target: String,
        arguments: Vec<Value>,
    },
    /// Tell the client why, then end the connection.
    Closing(String),
}

enum Kind {
    Hub(mpsc::UnboundedSender<HubOut>),
    Stream(mpsc::UnboundedSender<String>),
}

struct Session {
    client_id: String,
    generation: u32,
    kind: Kind,
    ended: bool,
}

/// Every hub connection and stream that is open.
pub(crate) struct Sessions {
    state: Arc<ServerState>,
    sessions: Mutex<HashMap<u64, Session>>,
    next: AtomicU64,
    stopping: AtomicBool,
}

/// Lets go of a session when dropped.
pub(crate) struct SessionGuard {
    sessions: Arc<Sessions>,
    id: u64,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.sessions
            .sessions
            .lock()
            .expect("sessions lock")
            .remove(&self.id);
    }
}

impl Sessions {
    pub(crate) fn new(state: Arc<ServerState>) -> Arc<Self> {
        Arc::new(Self {
            state,
            sessions: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
            stopping: AtomicBool::new(false),
        })
    }

    /// Watches the state: ends the sessions of a client that was revoked or whose secret was
    /// rotated, and tells hub connections when the certificates change. Ends with the server.
    pub(crate) fn spawn_watch(self: &Arc<Self>) {
        let weak: Weak<Self> = Arc::downgrade(self);
        let mut changes = self.state.subscribe();
        let mut certificates = certificates_of(&self.state);
        tokio::spawn(async move {
            while changes.changed().await.is_ok() {
                let Some(sessions) = weak.upgrade() else {
                    return;
                };
                sessions.end_stale();
                let now = certificates_of(&sessions.state);
                if now != certificates {
                    certificates = now.clone();
                    sessions.send_certificates(&now);
                }
            }
        });
    }

    pub(crate) fn add_hub(
        self: &Arc<Self>,
        client_id: &str,
        generation: u32,
        out: mpsc::UnboundedSender<HubOut>,
    ) -> SessionGuard {
        self.add(client_id, generation, Kind::Hub(out))
    }

    pub(crate) fn add_stream(
        self: &Arc<Self>,
        client_id: &str,
        generation: u32,
        end: mpsc::UnboundedSender<String>,
    ) -> SessionGuard {
        self.add(client_id, generation, Kind::Stream(end))
    }

    fn add(self: &Arc<Self>, client_id: &str, generation: u32, kind: Kind) -> SessionGuard {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let mut session = Session {
            client_id: client_id.to_owned(),
            generation,
            kind,
            ended: false,
        };
        if self.stopping.load(Ordering::Acquire) {
            end(&mut session, CLOSING_STOPPING);
        } else if !self.state.loaded().is_current(client_id, generation) {
            let reason = self.reason_for(client_id);
            end(&mut session, reason);
        }
        self.sessions
            .lock()
            .expect("sessions lock")
            .insert(id, session);
        SessionGuard {
            sessions: self.clone(),
            id,
        }
    }

    /// Ends every session with `reason`. With `stopping`, also ends any added later.
    pub(crate) fn end_all(&self, reason: &str) {
        if reason == CLOSING_STOPPING {
            self.stopping.store(true, Ordering::Release);
        }
        for session in self.sessions.lock().expect("sessions lock").values_mut() {
            end(session, reason);
        }
    }

    /// How many sessions of this client are open.
    pub(crate) fn count_for(&self, client_id: &str) -> usize {
        self.sessions
            .lock()
            .expect("sessions lock")
            .values()
            .filter(|s| s.client_id == client_id)
            .count()
    }

    fn end_stale(&self) {
        let loaded = self.state.loaded();
        let mut sessions = self.sessions.lock().expect("sessions lock");
        for session in sessions.values_mut() {
            if !loaded.is_current(&session.client_id, session.generation) {
                let reason = if loaded.find(&session.client_id).is_none() {
                    CLOSING_REVOKED
                } else {
                    CLOSING_ROTATED
                };
                end(session, reason);
            }
        }
    }

    fn reason_for(&self, client_id: &str) -> &'static str {
        if self.state.loaded().find(client_id).is_none() {
            CLOSING_REVOKED
        } else {
            CLOSING_ROTATED
        }
    }

    fn send_certificates(&self, certificates: &SkakelCertificates) {
        let loaded = self.state.loaded();
        let argument = serde_json::to_value(certificates).expect("certificates are JSON");
        for session in self.sessions.lock().expect("sessions lock").values() {
            if let Kind::Hub(out) = &session.kind
                && !session.ended
                && loaded.is_current(&session.client_id, session.generation)
            {
                let _ = out.send(HubOut::Invoke {
                    target: HUB_CERTIFICATES.to_owned(),
                    arguments: vec![argument.clone()],
                });
            }
        }
    }
}

fn end(session: &mut Session, reason: &str) {
    if session.ended {
        return;
    }
    session.ended = true;
    match &session.kind {
        Kind::Hub(out) => {
            let _ = out.send(HubOut::Closing(reason.to_owned()));
        }
        Kind::Stream(end) => {
            let _ = end.send(reason.to_owned());
        }
    }
}

/// The certificates the server presents and will present next, as the hub says them.
pub(crate) fn certificates_of(state: &ServerState) -> SkakelCertificates {
    let loaded = state.loaded();
    SkakelCertificates {
        fingerprint: loaded.fingerprint.clone(),
        next_fingerprint: loaded.next_fingerprint.clone(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::events::Events;
    use crate::store::InMemoryStore;

    async fn sessions() -> (Arc<Sessions>, Arc<ServerState>) {
        let state = ServerState::start(
            Arc::new(InMemoryStore::new()),
            false,
            "pi-lab".into(),
            "t".into(),
            Events::new(vec![]),
        )
        .await
        .unwrap();
        let sessions = Sessions::new(state.clone());
        sessions.spawn_watch();
        (sessions, state)
    }

    async fn closing(rx: &mut mpsc::UnboundedReceiver<HubOut>) -> String {
        match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
            Ok(Some(HubOut::Closing(reason))) => reason,
            Ok(Some(HubOut::Invoke { target, .. })) => panic!("unexpected {target}"),
            other => panic!("no closing: {}", other.is_ok()),
        }
    }

    #[tokio::test]
    async fn revoking_a_client_ends_its_hub_and_its_streams_with_revoked() {
        let (sessions, state) = sessions().await;
        let client = state.register_client("lab pc").await.unwrap();
        let (hub_tx, mut hub_rx) = mpsc::unbounded_channel();
        let (stream_tx, mut stream_rx) = mpsc::unbounded_channel();
        let _hub = sessions.add_hub(&client.client_id, 1, hub_tx);
        let _stream = sessions.add_stream(&client.client_id, 1, stream_tx);

        state.revoke_client(&client.client_id).await.unwrap();

        assert_eq!(closing(&mut hub_rx).await, "revoked");
        let reason = tokio::time::timeout(Duration::from_secs(5), stream_rx.recv()).await;
        assert_eq!(reason.unwrap().as_deref(), Some("revoked"));
    }

    #[tokio::test]
    async fn rotating_a_secret_ends_the_old_generation_with_rotated_and_leaves_others() {
        let (sessions, state) = sessions().await;
        let a = state.register_client("a").await.unwrap();
        let b = state.register_client("b").await.unwrap();
        let (a_tx, mut a_rx) = mpsc::unbounded_channel();
        let (b_tx, mut b_rx) = mpsc::unbounded_channel();
        let _a = sessions.add_hub(&a.client_id, 1, a_tx);
        let _b = sessions.add_hub(&b.client_id, 1, b_tx);

        state.rotate_secret(&a.client_id).await.unwrap();

        assert_eq!(closing(&mut a_rx).await, "rotated");
        assert!(b_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn a_session_added_for_a_client_that_is_gone_is_ended_at_once() {
        let (sessions, _) = sessions().await;
        let (tx, mut rx) = mpsc::unbounded_channel();

        let _guard = sessions.add_hub("client-gone", 1, tx);

        assert_eq!(closing(&mut rx).await, "revoked");
    }

    #[tokio::test]
    async fn stopping_ends_everything_and_everything_added_after() {
        let (sessions, state) = sessions().await;
        let client = state.register_client("lab pc").await.unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let _guard = sessions.add_hub(&client.client_id, 1, tx);

        sessions.end_all("stopping");
        let (late_tx, mut late_rx) = mpsc::unbounded_channel();
        let _late = sessions.add_hub(&client.client_id, 1, late_tx);

        assert_eq!(closing(&mut rx).await, "stopping");
        assert_eq!(closing(&mut late_rx).await, "stopping");
    }

    #[tokio::test]
    async fn a_certificate_change_is_sent_to_hub_connections_only() {
        let (sessions, state) = sessions().await;
        let client = state.register_client("lab pc").await.unwrap();
        let (hub_tx, mut hub_rx) = mpsc::unbounded_channel();
        let (stream_tx, mut stream_rx) = mpsc::unbounded_channel();
        let _hub = sessions.add_hub(&client.client_id, 1, hub_tx);
        let _stream = sessions.add_stream(&client.client_id, 1, stream_tx);

        let next = state.prepare_certificate().await.unwrap().unwrap();

        match tokio::time::timeout(Duration::from_secs(5), hub_rx.recv()).await {
            Ok(Some(HubOut::Invoke { target, arguments })) => {
                assert_eq!(target, "SkakelCertificates");
                assert_eq!(arguments[0]["nextFingerprint"], next.as_str());
                assert_eq!(arguments[0]["fingerprint"], state.fingerprint().as_str());
            }
            _ => panic!("no certificates"),
        }
        assert!(stream_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn a_dropped_guard_forgets_the_session() {
        let (sessions, state) = sessions().await;
        let client = state.register_client("lab pc").await.unwrap();
        let (tx, _rx) = mpsc::unbounded_channel();

        let guard = sessions.add_hub(&client.client_id, 1, tx);
        assert_eq!(sessions.count_for(&client.client_id), 1);
        drop(guard);

        assert_eq!(sessions.count_for(&client.client_id), 0);
    }
}
