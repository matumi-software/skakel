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
        }
    }
}

impl std::fmt::Debug for ClientOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientOptions")
            .field("request_timeout", &self.request_timeout)
            .field("browser", &self.browser.is_some())
            .finish_non_exhaustive()
    }
}
