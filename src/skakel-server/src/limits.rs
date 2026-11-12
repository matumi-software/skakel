//! The per-address limits and the failed-secret limit: fixed one-minute windows.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

use crate::util::address_key;

/// How long a window lasts.
const WINDOW: Duration = Duration::from_secs(60);

/// Wrong secrets one client may send from one address in a window before that address is answered
/// 429 for that client. Wrong secrets from one address never lock a client out for the others.
pub(crate) const TOKEN_FAILURES_PER_CLIENT_PER_ADDRESS_PER_MINUTE: u32 = 10;

/// When the map holds this many keys, the ones whose window is over are dropped.
const PRUNE_AT: usize = 4096;

/// The map is swept at most this often, so a flood of live keys does not cost a full pass per call.
const PRUNE_EVERY: Duration = Duration::from_secs(5);

/// The most keys one limiter holds. A call under a key it does not hold yet is refused past this,
/// so memory stays bounded however many addresses a flood comes from.
const MAX_KEYS: usize = 100_000;

#[derive(Default)]
struct Counts {
    keys: HashMap<String, (Instant, u32)>,
    last_prune: Option<Instant>,
    #[cfg(test)]
    prunes: u32,
}

/// A fixed window limiter keyed by text.
struct Window {
    permits: u32,
    counts: Mutex<Counts>,
}

impl Window {
    fn new(permits: u32) -> Self {
        Self {
            permits,
            counts: Mutex::new(Counts::default()),
        }
    }

    /// Takes one permit; false when the window has none left, or the limiter is full of other
    /// keys.
    fn try_take(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut guard = self.counts.lock().expect("limits lock");
        let counts = &mut *guard;
        if counts.keys.len() >= PRUNE_AT
            && counts.last_prune.is_none_or(|at| at + PRUNE_EVERY <= now)
        {
            counts.keys.retain(|_, (start, _)| *start + WINDOW > now);
            counts.last_prune = Some(now);
            #[cfg(test)]
            {
                counts.prunes += 1;
            }
        }
        if counts.keys.len() >= MAX_KEYS && !counts.keys.contains_key(key) {
            return false;
        }
        let entry = counts.keys.entry(key.to_owned()).or_insert((now, 0));
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
            .keys
            .get(key)
            .is_some_and(|(start, count)| *start + WINDOW > now && *count >= self.permits)
    }
}

fn failure_key(client_id: &str, from: IpAddr) -> String {
    format!("{client_id}\n{}", address_key(from))
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
            token_failures: Window::new(TOKEN_FAILURES_PER_CLIENT_PER_ADDRESS_PER_MINUTE),
        }
    }

    pub(crate) fn try_token(&self, from: IpAddr) -> bool {
        self.token.try_take(&address_key(from))
    }

    pub(crate) fn try_pair(&self, from: IpAddr) -> bool {
        self.pair.try_take(&address_key(from))
    }

    /// Whether `from` has sent too many wrong secrets for this client this minute.
    pub(crate) fn too_many_failures(&self, client_id: &str, from: IpAddr) -> bool {
        self.token_failures.is_full(&failure_key(client_id, from))
    }

    pub(crate) fn count_failure(&self, client_id: &str, from: IpAddr) {
        self.token_failures.try_take(&failure_key(client_id, from));
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
    async fn a_mapped_address_counts_as_its_ipv4_address_and_ipv6_counts_by_its_64() {
        let limits = Limits::new(1, 120);

        assert!(limits.try_token(ip("10.0.0.1")));
        assert!(!limits.try_token(ip("::ffff:10.0.0.1")));
        assert!(limits.try_token(ip("2001:db8::1")));
        assert!(!limits.try_token(ip("2001:db8::2")));
        assert!(!limits.try_token(ip("2001:db8:0:0:ffff::1")));
        assert!(limits.try_token(ip("2001:db8:0:1::1")));
    }

    #[tokio::test(start_paused = true)]
    async fn ten_failures_stop_that_address_for_that_client_until_the_minute_is_up() {
        let limits = Limits::new(60, 120);
        let (client, address) = ("client-1", ip("10.0.0.1"));

        for _ in 0..10 {
            assert!(!limits.too_many_failures(client, address));
            limits.count_failure(client, address);
        }

        assert!(limits.too_many_failures(client, address));
        assert!(!limits.too_many_failures("client-2", address));
        tokio::time::advance(Duration::from_secs(60)).await;
        assert!(!limits.too_many_failures(client, address));
    }

    #[tokio::test(start_paused = true)]
    async fn wrong_secrets_from_one_address_never_lock_a_client_out_for_another() {
        let limits = Limits::new(60, 120);

        for _ in 0..50 {
            limits.count_failure("client-1", ip("10.0.0.9"));
        }

        assert!(limits.too_many_failures("client-1", ip("10.0.0.9")));
        assert!(!limits.too_many_failures("client-1", ip("10.0.0.1")));
        assert!(!limits.too_many_failures("client-1", ip("2001:db8::1")));
    }

    #[tokio::test(start_paused = true)]
    async fn a_flood_of_live_keys_is_swept_every_few_seconds_and_not_on_every_call() {
        let window = Window::new(1);
        for n in 0..PRUNE_AT + 50 {
            assert!(window.try_take(&format!("key-{n}")));
        }

        for n in 0..1000 {
            window.try_take(&format!("more-{n}"));
        }

        assert_eq!(window.counts.lock().unwrap().prunes, 1);
        tokio::time::advance(WINDOW).await;
        window.try_take("late");
        let counts = window.counts.lock().unwrap();
        assert_eq!(counts.prunes, 2);
        assert_eq!(counts.keys.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_limiter_full_of_keys_refuses_a_new_one_and_still_counts_the_old() {
        let window = Window::new(2);
        for n in 0..MAX_KEYS {
            assert!(window.try_take(&format!("key-{n}")));
        }

        assert!(!window.try_take("new"));
        assert!(window.try_take("key-0"));
        assert!(!window.try_take("key-0"));
        assert_eq!(window.counts.lock().unwrap().keys.len(), MAX_KEYS);
    }
}
