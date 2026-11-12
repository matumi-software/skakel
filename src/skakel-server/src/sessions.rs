//! The calls that are running, Skakel's and the app's, and ending them when their client is
//! revoked, its secret rotated or the server stops.
//!
//! A control call (`ControlService.Connect`) is told the certificates whenever they change, and
//! `closing` before it ends. Every other call that stays open, a stream or an app's call, is only
//! told to end, with the reason.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use skakel_proto::v2::Certificates;
use skakel_wire::Reason;
use tokio::sync::{Notify, mpsc, oneshot};

use crate::state::ServerState;

/// What the server tells a control call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ControlOut {
    /// The certificates changed.
    Certificates(Certificates),
    /// Say `closing` with this reason, then end the call with its status.
    Closing(Reason),
}

enum Kind {
    Control(mpsc::UnboundedSender<ControlOut>),
    Call(Option<oneshot::Sender<Reason>>),
}

struct Session {
    client_id: String,
    generation: u32,
    kind: Kind,
    ended: bool,
}

/// Every call that is running.
pub(crate) struct Sessions {
    state: Arc<ServerState>,
    sessions: Mutex<HashMap<u64, Session>>,
    next: AtomicU64,
    stopping: AtomicBool,
    emptied: Notify,
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
        self.sessions.emptied.notify_waiters();
    }
}

impl Sessions {
    pub(crate) fn new(state: Arc<ServerState>) -> Arc<Self> {
        Arc::new(Self {
            state,
            sessions: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
            stopping: AtomicBool::new(false),
            emptied: Notify::new(),
        })
    }

    /// Watches the state: ends the calls of a client that was revoked or whose secret was rotated,
    /// and tells control calls when the certificates change. Ends with the server.
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

    /// A control call of a client at a generation. It hears [`ControlOut`] on `out`.
    pub(crate) fn add_control(
        self: &Arc<Self>,
        client_id: &str,
        generation: u32,
        out: mpsc::UnboundedSender<ControlOut>,
    ) -> SessionGuard {
        self.add(client_id, generation, Kind::Control(out))
    }

    /// Any other call that stays open. The receiver hears why, once, when it has to end.
    pub(crate) fn add_call(
        self: &Arc<Self>,
        client_id: &str,
        generation: u32,
    ) -> (SessionGuard, oneshot::Receiver<Reason>) {
        let (end, ended) = oneshot::channel();
        let guard = self.add(client_id, generation, Kind::Call(Some(end)));
        (guard, ended)
    }

    fn add(self: &Arc<Self>, client_id: &str, generation: u32, kind: Kind) -> SessionGuard {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let mut session = Session {
            client_id: client_id.to_owned(),
            generation,
            kind,
            ended: false,
        };
        // Checked under the lock, so a revoke or a stop between the token check and here still
        // reaches the call.
        let mut sessions = self.sessions.lock().expect("sessions lock");
        if self.stopping.load(Ordering::Acquire) {
            end(&mut session, Reason::Stopping);
        } else if !self.state.loaded().is_current(client_id, generation) {
            let reason = self.reason_for(client_id);
            end(&mut session, reason);
        }
        sessions.insert(id, session);
        SessionGuard {
            sessions: self.clone(),
            id,
        }
    }

    /// Ends every call with `reason`. With [`Reason::Stopping`], also ends any added later.
    pub(crate) fn end_all(&self, reason: Reason) {
        let mut sessions = self.sessions.lock().expect("sessions lock");
        if reason == Reason::Stopping {
            self.stopping.store(true, Ordering::Release);
        }
        for session in sessions.values_mut() {
            end(session, reason);
        }
    }

    /// Waits until no call is running, or `bound` has passed. True when none is. A call is gone
    /// when its task has handed its closing message and status on, so after this the connections
    /// can be asked to wind down without losing them.
    pub(crate) async fn wait_until_empty(&self, bound: std::time::Duration) -> bool {
        tokio::time::timeout(bound, async {
            loop {
                let notified = self.emptied.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.sessions.lock().expect("sessions lock").is_empty() {
                    return;
                }
                notified.await;
            }
        })
        .await
        .is_ok()
    }

    /// How many calls of this client are running.
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
                    Reason::Revoked
                } else {
                    Reason::Rotated
                };
                end(session, reason);
            }
        }
    }

    fn reason_for(&self, client_id: &str) -> Reason {
        if self.state.loaded().find(client_id).is_none() {
            Reason::Revoked
        } else {
            Reason::Rotated
        }
    }

    fn send_certificates(&self, certificates: &Certificates) {
        let loaded = self.state.loaded();
        for session in self.sessions.lock().expect("sessions lock").values() {
            if let Kind::Control(out) = &session.kind
                && !session.ended
                && loaded.is_current(&session.client_id, session.generation)
            {
                let _ = out.send(ControlOut::Certificates(certificates.clone()));
            }
        }
    }
}

fn end(session: &mut Session, reason: Reason) {
    if session.ended {
        return;
    }
    session.ended = true;
    match &mut session.kind {
        Kind::Control(out) => {
            let _ = out.send(ControlOut::Closing(reason));
        }
        Kind::Call(end) => {
            if let Some(end) = end.take() {
                let _ = end.send(reason);
            }
        }
    }
}

/// The certificates the server presents and will present next, as the control channel says them:
/// an empty next fingerprint when none is prepared.
pub(crate) fn certificates_of(state: &ServerState) -> Certificates {
    let loaded = state.loaded();
    Certificates {
        fingerprint: loaded.fingerprint.clone(),
        next_fingerprint: loaded.next_fingerprint.clone().unwrap_or_default(),
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
            Events::new(),
        )
        .await
        .unwrap();
        let sessions = Sessions::new(state.clone());
        sessions.spawn_watch();
        (sessions, state)
    }

    async fn closing(rx: &mut mpsc::UnboundedReceiver<ControlOut>) -> Reason {
        match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
            Ok(Some(ControlOut::Closing(reason))) => reason,
            Ok(Some(other)) => panic!("unexpected {other:?}"),
            other => panic!("no closing: {}", other.is_ok()),
        }
    }

    async fn ended(rx: oneshot::Receiver<Reason>) -> Reason {
        tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .expect("ended in time")
            .expect("told why")
    }

    #[tokio::test]
    async fn revoking_a_client_ends_its_control_calls_and_its_other_calls_with_revoked() {
        let (sessions, state) = sessions().await;
        let client = state.register_client("lab pc").await.unwrap();
        let (control_tx, mut control_rx) = mpsc::unbounded_channel();
        let _control = sessions.add_control(&client.client_id, 1, control_tx);
        let (_call, call_ended) = sessions.add_call(&client.client_id, 1);

        state.revoke_client(&client.client_id).await.unwrap();

        assert_eq!(closing(&mut control_rx).await, Reason::Revoked);
        assert_eq!(ended(call_ended).await, Reason::Revoked);
    }

    #[tokio::test]
    async fn rotating_a_secret_ends_the_old_generation_with_rotated_and_leaves_others() {
        let (sessions, state) = sessions().await;
        let a = state.register_client("a").await.unwrap();
        let b = state.register_client("b").await.unwrap();
        let (a_tx, mut a_rx) = mpsc::unbounded_channel();
        let (b_tx, mut b_rx) = mpsc::unbounded_channel();
        let _a = sessions.add_control(&a.client_id, 1, a_tx);
        let _b = sessions.add_control(&b.client_id, 1, b_tx);

        state.rotate_secret(&a.client_id).await.unwrap();

        assert_eq!(closing(&mut a_rx).await, Reason::Rotated);
        assert!(b_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn a_call_added_for_a_client_that_is_gone_is_ended_at_once() {
        let (sessions, _) = sessions().await;
        let (tx, mut rx) = mpsc::unbounded_channel();

        let _guard = sessions.add_control("client-gone", 1, tx);
        let (_call, call_ended) = sessions.add_call("client-gone", 1);

        assert_eq!(closing(&mut rx).await, Reason::Revoked);
        assert_eq!(ended(call_ended).await, Reason::Revoked);
    }

    #[tokio::test]
    async fn stopping_ends_everything_and_everything_added_after() {
        let (sessions, state) = sessions().await;
        let client = state.register_client("lab pc").await.unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let _guard = sessions.add_control(&client.client_id, 1, tx);

        sessions.end_all(Reason::Stopping);
        let (late_tx, mut late_rx) = mpsc::unbounded_channel();
        let _late = sessions.add_control(&client.client_id, 1, late_tx);
        let (_call, call_ended) = sessions.add_call(&client.client_id, 1);

        assert_eq!(closing(&mut rx).await, Reason::Stopping);
        assert_eq!(closing(&mut late_rx).await, Reason::Stopping);
        assert_eq!(ended(call_ended).await, Reason::Stopping);
    }

    #[tokio::test]
    async fn a_certificate_change_is_sent_to_control_calls_only() {
        let (sessions, state) = sessions().await;
        let client = state.register_client("lab pc").await.unwrap();
        let (control_tx, mut control_rx) = mpsc::unbounded_channel();
        let _control = sessions.add_control(&client.client_id, 1, control_tx);
        let (_call, mut call_ended) = sessions.add_call(&client.client_id, 1);

        let next = state.prepare_certificate().await.unwrap().unwrap();

        match tokio::time::timeout(Duration::from_secs(5), control_rx.recv()).await {
            Ok(Some(ControlOut::Certificates(certificates))) => {
                assert_eq!(certificates.next_fingerprint, next);
                assert_eq!(certificates.fingerprint, state.fingerprint());
            }
            _ => panic!("no certificates"),
        }
        assert!(call_ended.try_recv().is_err());
    }

    #[tokio::test]
    async fn a_dropped_guard_forgets_the_call() {
        let (sessions, state) = sessions().await;
        let client = state.register_client("lab pc").await.unwrap();
        let (tx, _rx) = mpsc::unbounded_channel();

        let guard = sessions.add_control(&client.client_id, 1, tx);
        let (call, _ended) = sessions.add_call(&client.client_id, 1);
        assert_eq!(sessions.count_for(&client.client_id), 2);
        drop(guard);
        drop(call);

        assert_eq!(sessions.count_for(&client.client_id), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn waiting_for_the_calls_to_end_returns_as_the_last_one_goes() {
        let (sessions, state) = sessions().await;
        let client = state.register_client("lab pc").await.unwrap();
        let (guard, ended_rx) = sessions.add_call(&client.client_id, 1);
        sessions.end_all(Reason::Stopping);
        assert_eq!(ended(ended_rx).await, Reason::Stopping);

        let waiting = {
            let sessions = sessions.clone();
            tokio::spawn(async move { sessions.wait_until_empty(Duration::from_secs(5)).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiting.is_finished());
        drop(guard);

        assert!(waiting.await.unwrap());
    }

    #[tokio::test(start_paused = true)]
    async fn waiting_for_the_calls_to_end_gives_up_at_its_bound() {
        let (sessions, state) = sessions().await;
        let client = state.register_client("lab pc").await.unwrap();
        let (_guard, _ended) = sessions.add_call(&client.client_id, 1);

        assert!(!sessions.wait_until_empty(Duration::from_secs(2)).await);
    }

    #[tokio::test(start_paused = true)]
    async fn waiting_with_no_calls_returns_at_once() {
        let (sessions, _) = sessions().await;

        assert!(sessions.wait_until_empty(Duration::from_secs(2)).await);
    }
}
