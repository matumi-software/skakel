//! The clock a client keeps time by, so a test can move it. The system's unless set.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, SystemTime};

/// A future that finishes when a wait is over.
pub type Sleep = Pin<Box<dyn Future<Output = ()> + Send>>;

/// What the client asks of time: what time it is, and a wait. Token lifetimes, the hub's renewal,
/// the pause between attempts and the pairing poll all go through it.
pub trait Clock: Send + Sync + 'static {
    /// The time now.
    fn now(&self) -> SystemTime;

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

    fn sleep(&self, duration: Duration) -> Sleep {
        Box::pin(tokio::time::sleep(duration))
    }
}

/// `later - earlier`, or zero when `later` is not later.
pub(crate) fn since(later: SystemTime, earlier: SystemTime) -> Duration {
    later.duration_since(earlier).unwrap_or_default()
}
