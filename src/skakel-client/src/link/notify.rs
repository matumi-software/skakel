//! What a link tells the app and what it asks of it: its events, and the store that
//! keeps the pins.

use super::*;

/// What saving the pins may fail with.
pub type StoreError = Box<dyn std::error::Error + Send + Sync>;

/// What [`PinStore::save`] gives back.
pub type SaveFuture = Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send>>;

/// Where an app keeps the pins of a server, so a certificate handover survives a restart. The link
/// hands every change of its pins to it and tells the server it has the next certificate only once
/// `save` has returned `Ok`; a save that fails, or panics, is taken as not saved, and the server
/// says it again on the next connection.
///
/// Any `Fn(Pins) -> impl Future<Output = Result<(), E>>` is one:
///
/// ```no_run
/// # fn demo(link: &skakel_client::Link) {
/// link.set_pin_store(|pins: skakel_client::Pins| async move {
///     std::fs::write("pins.txt", pins.fingerprint())?;
///     Ok::<(), std::io::Error>(())
/// });
/// # }
/// ```
pub trait PinStore: Send + Sync + 'static {
    /// Saves the pins.
    fn save(&self, pins: Pins) -> SaveFuture;
}

impl<F, Fut, E> PinStore for F
where
    F: Fn(Pins) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), E>> + Send + 'static,
    E: Into<StoreError>,
{
    fn save(&self, pins: Pins) -> SaveFuture {
        let saving = self(pins);
        Box::pin(async move { saving.await.map_err(Into::into) })
    }
}

/// Something that happened to a link, in order. See [`Link::events`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinkEvent {
    /// The link's state or failure changed. Renewing the control call before its token runs out is
    /// not a change. An app whose own services push state calls them again when the link is
    /// [`LinkState::Connected`] after it was not, since the calls of a lost connection are over.
    Status(LinkStatus),
    /// The link followed its server to another address on the local network. Save the address.
    AddressChanged(Url),
    /// The server's word about its certificates changed the pins: a next one to trust as well, a
    /// switch to it, or a cancelled one. The [`PinStore`] has them too.
    PinsChanged(Pins),
}

/// How many events a slow subscriber may fall behind.
pub(super) const EVENT_BACKLOG: usize = 64;

/// Hands the pins to the app's store. True when it saved them, or when there is no store. The store
/// runs on a task of its own, so one that panics cannot take the link down with it.
pub(super) async fn save_pins(inner: &Inner, pins: Pins) -> bool {
    let store = lock(&inner.pin_store).clone();
    let Some(store) = store else {
        return true;
    };
    let saving = tokio::spawn(async move { store.save(pins).await });
    match saving.await {
        Ok(Ok(())) => true,
        Ok(Err(error)) => {
            log::warn!("The pin store failed to save the pins: {error}");
            false
        }
        Err(error) => {
            log::warn!("The pin store panicked while saving the pins: {error}");
            false
        }
    }
}
