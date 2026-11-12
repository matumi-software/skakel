//! The clock a client keeps time by, so a test can move it. The system's unless set.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant, SystemTime};

/// A future that finishes when a wait is over.
pub type Sleep = Pin<Box<dyn Future<Output = ()> + Send>>;

/// What the client asks of time: what time it is, how much has passed, and a wait. Token lifetimes,
/// the control call's renewal, the pause between attempts and the pairing poll all go through it.
pub trait Clock: Send + Sync + 'static {
    /// The wall-clock time now. Only for comparing with a time a server wrote down, such as when a
    /// pairing request runs out; everything that measures how long something lasts uses
    /// [`instant`](Self::instant), which a change of the system's clock does not move.
    fn now(&self) -> SystemTime;

    /// A monotonic instant: it only moves forward, at the rate time passes.
    fn instant(&self) -> Instant;

    /// Finishes after `duration` has passed on this clock.
    fn sleep(&self, duration: Duration) -> Sleep;
}

/// The system's clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }

    fn instant(&self) -> Instant {
        Instant::now()
    }

    fn sleep(&self, duration: Duration) -> Sleep {
        Box::pin(tokio::time::sleep(duration))
    }
}

/// `later - earlier`, or zero when `later` is not later.
pub(crate) fn since(later: Instant, earlier: Instant) -> Duration {
    later.saturating_duration_since(earlier)
}

/// `later - earlier` on the wall clock, or zero when `later` is not later.
pub(crate) fn wall_since(later: SystemTime, earlier: SystemTime) -> Duration {
    later.duration_since(earlier).unwrap_or_default()
}
