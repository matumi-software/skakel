//! The per-address and per-client limits: fixed one-minute windows, as the .NET server counts.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

use crate::util::address_key;

/// How long a window lasts.
const WINDOW: Duration = Duration::from_secs(60);

/// Wrong secrets one client may have in a window before it is answered 429.
pub(crate) const TOKEN_FAILURES_PER_CLIENT_PER_MINUTE: u32 = 10;

/// When the map holds this many keys, the ones whose window is over are dropped.
const PRUNE_AT: usize = 4096;

/// A fixed window limiter keyed by text.
struct Window {
    permits: u32,
    counts: Mutex<HashMap<String, (Instant, u32)>>,
}

impl Window {
    fn new(permits: u32) -> Self {
        Self {
            permits,
            counts: Mutex::new(HashMap::new()),
        }
    }

    /// Takes one permit; false when the window has none left.
    fn try_take(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut counts = self.counts.lock().expect("limits lock");
        if counts.len() >= PRUNE_AT {
            counts.retain(|_, (start, _)| *start + WINDOW > now);
        }
        let entry = counts.entry(key.to_owned()).or_insert((now, 0));
        if entry.0 + WINDOW <= now {
            *entry = (now, 0);
        }
        if entry.1 >= self.permits {
            return false;
        }
        entry.1 += 1;
        true
    }

    /// Whether the window has no permit left, without taking one.
    fn is_full(&self, key: &str) -> bool {
        let now = Instant::now();
        let counts = self.counts.lock().expect("limits lock");
        counts
            .get(key)
            .is_some_and(|(start, count)| *start + WINDOW > now && *count >= self.permits)
    }
}

/// The server's three limiters.
pub(crate) struct Limits {
    token: Window,
    pair: Window,
    token_failures: Window,
}

impl Limits {
    pub(crate) fn new(token_per_minute: u32, pair_per_minute: u32) -> Self {
        Self {
            token: Window::new(token_per_minute),
            pair: Window::new(pair_per_minute),
            token_failures: Window::new(TOKEN_FAILURES_PER_CLIENT_PER_MINUTE),
        }
    }

    pub(crate) fn try_token(&self, from: IpAddr) -> bool {
        self.token.try_take(&address_key(from))
    }

    pub(crate) fn try_pair(&self, from: IpAddr) -> bool {
        self.pair.try_take(&address_key(from))
    }

    pub(crate) fn too_many_failures(&self, client_id: &str) -> bool {
        self.token_failures.is_full(client_id)
    }

    pub(crate) fn count_failure(&self, client_id: &str) {
        self.token_failures.try_take(client_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn an_address_gets_its_permits_and_then_waits_for_the_next_minute() {
        let limits = Limits::new(3, 120);

        assert!((0..3).all(|_| limits.try_token(ip("10.0.0.1"))));
        assert!(!limits.try_token(ip("10.0.0.1")));
        assert!(limits.try_token(ip("10.0.0.2")));

        tokio::time::advance(Duration::from_secs(59)).await;
        assert!(!limits.try_token(ip("10.0.0.1")));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(limits.try_token(ip("10.0.0.1")));
    }

    #[tokio::test(start_paused = true)]
    async fn token_and_pair_calls_are_counted_apart() {
        let limits = Limits::new(1, 1);

        assert!(limits.try_token(ip("10.0.0.1")));
        assert!(limits.try_pair(ip("10.0.0.1")));
        assert!(!limits.try_token(ip("10.0.0.1")));
        assert!(!limits.try_pair(ip("10.0.0.1")));
    }

    #[tokio::test(start_paused = true)]
    async fn a_mapped_address_counts_as_its_ipv4_address_and_ipv6_counts_whole() {
        let limits = Limits::new(1, 120);

        assert!(limits.try_token(ip("10.0.0.1")));
        assert!(!limits.try_token(ip("::ffff:10.0.0.1")));
        assert!(limits.try_token(ip("2001:db8::1")));
        assert!(limits.try_token(ip("2001:db8::2")));
        assert!(!limits.try_token(ip("2001:db8::1")));
    }

    #[tokio::test(start_paused = true)]
    async fn ten_failures_stop_a_client_until_the_minute_is_up() {
        let limits = Limits::new(60, 120);

        for _ in 0..10 {
            assert!(!limits.too_many_failures("client-1"));
            limits.count_failure("client-1");
        }

        assert!(limits.too_many_failures("client-1"));
        assert!(!limits.too_many_failures("client-2"));
        tokio::time::advance(Duration::from_secs(60)).await;
        assert!(!limits.too_many_failures("client-1"));
    }
}
