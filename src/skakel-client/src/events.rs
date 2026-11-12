//! How the client tells an app that something changed, in two shapes that every part uses.
//!
//! - **State**: what is true now. A [`StateWatch`] holds the latest value, wakes when it changes,
//!   and may skip values it was not asked about in between. A link's status, its address and its
//!   pins, the browser's list of servers.
//! - **Events**: things that happened, in order. [`Events`] is a receiver of them; one that is not
//!   read for long enough misses the oldest and says how many. A link's changes of status, its move
//!   to another address, the port's errors.
//!
//! Neither runs the app's code: a part never waits for a subscriber, so a slow or failing one cannot
//! hold up a link.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::sync::{broadcast, watch};
use tokio_stream::Stream;
use tokio_stream::wrappers::{BroadcastStream, WatchStream};

/// Why a receiver gave nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventsError {
    /// The sender is gone: the link, browser or connection was dropped.
    Closed,
    /// The receiver was not read in time and missed this many events. The next read goes on from
    /// the oldest one still held.
    Lagged(u64),
}

impl std::fmt::Display for EventsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => f.write_str("The source of these events is gone."),
            Self::Lagged(missed) => write!(f, "{missed} events were missed."),
        }
    }
}

impl std::error::Error for EventsError {}

/// The latest value of something, and a wait for it to change. Cheap to clone.
///
/// ```no_run
/// # async fn show(mut status: skakel_client::StateWatch<skakel_client::LinkStatus>) {
/// println!("now {:?}", status.get().state);
/// while status.changed().await.is_ok() {
///     println!("now {:?}", status.get().state);
/// }
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct StateWatch<T> {
    receiver: watch::Receiver<T>,
}

impl<T: Clone> StateWatch<T> {
    pub(crate) fn new(receiver: watch::Receiver<T>) -> Self {
        Self { receiver }
    }

    /// The latest value.
    pub fn get(&self) -> T {
        self.receiver.borrow().clone()
    }

    /// Waits until the value changed since it was last looked at with [`get`](Self::get) or
    /// `changed`. Fails once the source is gone.
    pub async fn changed(&mut self) -> Result<(), EventsError> {
        self.receiver
            .changed()
            .await
            .map_err(|_| EventsError::Closed)
    }

    /// Waits until the value satisfies `condition`, and gives it. The current value counts.
    pub async fn wait_for(
        &mut self,
        mut condition: impl FnMut(&T) -> bool,
    ) -> Result<T, EventsError> {
        self.receiver
            .wait_for(|value| condition(value))
            .await
            .map(|value| value.clone())
            .map_err(|_| EventsError::Closed)
    }

    /// The values as a stream: the current one first, then each change.
    pub fn into_stream(self) -> impl Stream<Item = T> + Send + 'static
    where
        T: Send + Sync + 'static,
    {
        WatchStream::new(self.receiver)
    }
}

/// A receiver of events, in the order they happened.
///
/// ```no_run
/// # async fn show(mut events: skakel_client::Events<skakel_client::LinkEvent>) {
/// while let Ok(event) = events.recv().await {
///     println!("{event:?}");
/// }
/// # }
/// ```
#[derive(Debug)]
pub struct Events<T> {
    receiver: broadcast::Receiver<T>,
}

impl<T: Clone> Events<T> {
    pub(crate) fn new(receiver: broadcast::Receiver<T>) -> Self {
        Self { receiver }
    }

    /// The next event.
    pub async fn recv(&mut self) -> Result<T, EventsError> {
        self.receiver.recv().await.map_err(|error| match error {
            broadcast::error::RecvError::Closed => EventsError::Closed,
            broadcast::error::RecvError::Lagged(missed) => EventsError::Lagged(missed),
        })
    }

    /// The next event if one is waiting.
    pub fn try_recv(&mut self) -> Result<Option<T>, EventsError> {
        match self.receiver.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(broadcast::error::TryRecvError::Empty) => Ok(None),
            Err(broadcast::error::TryRecvError::Closed) => Err(EventsError::Closed),
            Err(broadcast::error::TryRecvError::Lagged(missed)) => Err(EventsError::Lagged(missed)),
        }
    }

    /// The events as a stream, which ends when the source is gone. Events missed are skipped.
    pub fn into_stream(self) -> impl Stream<Item = T> + Send + 'static
    where
        T: Send + 'static,
    {
        EventStream {
            inner: BroadcastStream::new(self.receiver),
        }
    }
}

struct EventStream<T> {
    inner: BroadcastStream<T>,
}

impl<T: Clone + Send + 'static> Stream for EventStream<T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        loop {
            match Pin::new(&mut self.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(event))) => return Poll::Ready(Some(event)),
                Poll::Ready(Some(Err(_missed))) => continue,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_stream::StreamExt;

    #[tokio::test]
    async fn a_watch_gives_the_latest_value_and_says_when_it_changes() {
        let (tx, rx) = watch::channel(1);
        let mut state = StateWatch::new(rx);

        assert_eq!(state.get(), 1);
        tx.send_replace(2);
        state.changed().await.unwrap();

        assert_eq!(state.get(), 2);
        assert_eq!(state.wait_for(|v| *v == 2).await, Ok(2));
        drop(tx);
        assert_eq!(state.changed().await, Err(EventsError::Closed));
    }

    #[tokio::test]
    async fn events_come_in_order_and_a_slow_reader_is_told_what_it_missed() {
        let (tx, rx) = broadcast::channel(2);
        let mut events = Events::new(rx);
        for n in 1..=4 {
            tx.send(n).unwrap();
        }

        assert_eq!(events.recv().await, Err(EventsError::Lagged(2)));
        assert_eq!(events.recv().await, Ok(3));
        assert_eq!(events.try_recv(), Ok(Some(4)));
        assert_eq!(events.try_recv(), Ok(None));
        drop(tx);
        assert_eq!(events.recv().await, Err(EventsError::Closed));
    }

    #[tokio::test]
    async fn the_stream_forms_end_with_their_source() {
        let (tx, rx) = broadcast::channel(8);
        let events = Events::new(rx).into_stream();
        tx.send("a").unwrap();
        tx.send("b").unwrap();
        drop(tx);

        let all: Vec<_> = events.collect().await;

        assert_eq!(all, ["a", "b"]);
    }
}
