//! How the client's parts keep time and wait. The link settings apply to a [`Link`](crate::Link)
//! only.

use std::sync::Arc;
use std::time::Duration;

use crate::browser::Browser;
use crate::clock::{Clock, SystemClock};

/// How the client's parts keep time and wait.
#[derive(Clone)]
pub struct ClientOptions {
    /// The clock. The system's unless set.
    pub clock: Arc<dyn Clock>,
    /// How long one HTTP request may take. A server on slow hardware can take many seconds over its
    /// first request after a start.
    pub request_timeout: Duration,
    /// For a link: the hub's path under `/skakel/v1/`, as the app's server mapped it. `hub` unless
    /// set.
    pub hub_path: String,
    /// For a link: the browser it listens to, so it can follow its server to another address on the
    /// local network when the saved one stops answering. Without one, a link stays where it is.
    pub browser: Option<Browser>,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            clock: Arc::new(SystemClock),
            request_timeout: Duration::from_secs(30),
            hub_path: "hub".to_owned(),
            browser: None,
        }
    }
}

impl std::fmt::Debug for ClientOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientOptions")
            .field("request_timeout", &self.request_timeout)
            .field("hub_path", &self.hub_path)
            .field("browser", &self.browser.is_some())
            .finish_non_exhaustive()
    }
}
