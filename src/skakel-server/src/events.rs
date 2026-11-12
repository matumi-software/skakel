//! What the server tells the app as it happens: pairing requests waiting for a person, how they
//! ended, who the clients are and which keys are in use.

use tokio::sync::broadcast;

use crate::pairing::{PairingDecision, PairingOverview};
use crate::state::{ClientView, KeysView};

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
    Keys(KeysView),
}

/// An app's callback for what happens on the server.
pub(crate) type Callback = Box<dyn Fn(&ServerEvent) + Send + Sync>;

/// Delivers events to the app's callbacks and to anyone who subscribed.
pub(crate) struct Events {
    sender: broadcast::Sender<ServerEvent>,
    callbacks: Vec<Callback>,
}

impl Events {
    pub(crate) fn new(callbacks: Vec<Callback>) -> Self {
        let (sender, _) = broadcast::channel(64);
        Self { sender, callbacks }
    }

    pub(crate) fn emit(&self, event: ServerEvent) {
        for callback in &self.callbacks {
            // One app callback that panics must not take the server's tasks down with it.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| callback(&event)));
        }
        let _ = self.sender.send(event);
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<ServerEvent> {
        self.sender.subscribe()
    }
}
