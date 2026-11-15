//! How the client's parts keep time and wait. The link settings apply to a [`Link`](crate::Link)
//! only.

use std::sync::Arc;
use std::time::Duration;

use crate::browser::Browser;
use crate::clock::{Clock, SystemClock};

/// How the client's parts keep time and wait. Start from the default and change what you need:
///
/// ```
/// # use std::time::Duration;
/// let options = skakel_client::ClientOptions::default().request_timeout(Duration::from_secs(10));
/// ```
#[derive(Clone)]
#[non_exhaustive]
pub struct ClientOptions {
    /// The clock. The system's unless set.
    pub clock: Arc<dyn Clock>,
    /// How long one request may take: an HTTPS call, a gRPC connection and its handshake, the
    /// server's `certificates` on a new control call, or `opened` on a new stream. A server on slow
    /// hardware can take many seconds over its first request after a start.
    pub request_timeout: Duration,
    /// For a link: the browser it listens to, so it can follow its server to another address on the
    /// local network when the saved one stops answering. Without one, a link stays where it is.
    pub browser: Option<Browser>,
    /// For a link: wait this long between tries after a failure (the wait is a random time from half of
    /// this to all of it, so links do not all return at once, and never under a second). Without it
    /// the wait starts at a second and doubles up to a minute, and starts over once a link has
    /// stayed up for half a minute.
    pub retry_interval: Option<Duration>,
}

impl ClientOptions {
    /// Keeps time by `clock` instead of the system's.
    #[must_use]
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// How long one request may take.
    #[must_use]
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// For a link: a fixed wait between tries after a failure, instead of the doubling one.
    #[must_use]
    pub fn retry_interval(mut self, interval: Duration) -> Self {
        self.retry_interval = Some(interval);
        self
    }

    /// For a link: the browser to listen to, so it can follow its server to another address.
    #[must_use]
    pub fn browser(mut self, browser: Browser) -> Self {
        self.browser = Some(browser);
        self
    }
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            clock: Arc::new(SystemClock),
            request_timeout: Duration::from_secs(30),
            browser: None,
            retry_interval: None,
        }
    }
}

impl std::fmt::Debug for ClientOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientOptions")
            .field("request_timeout", &self.request_timeout)
            .field("browser", &self.browser.is_some())
            .field("retry_interval", &self.retry_interval)
            .finish_non_exhaustive()
    }
}
