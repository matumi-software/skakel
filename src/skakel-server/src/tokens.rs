//! Access tokens: random strings the server remembers.
//!
//! A client never reads a token, and every call is checked against the server's own state (the
//! client must still exist at the generation the token was issued for), so a token needs no
//! signature. It is 256 random bits, and the server keeps what it stands for in memory. That
//! drops the signing key and everything around it: nothing to rotate, nothing to keep on disk.
//! A server that restarts forgets its tokens, and a client whose token is refused simply asks for
//! a new one, which the protocol has it do anyway.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio::time::Instant;

use crate::util;

/// The most tokens one client holds at once. A client asks for a new one about every 28 minutes, so
/// this is far more than it needs; past it the client's oldest are forgotten.
const MAX_TOKENS_PER_CLIENT: usize = 32;

/// Expired tokens are swept when a token is issued and the last sweep was this long ago.
const SWEEP_EVERY: Duration = Duration::from_secs(60);

/// Who a valid token is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// The client's id.
    pub client_id: String,
    /// The client's generation when the token was issued.
    pub generation: u32,
    /// When the token expires.
    pub expires_at: OffsetDateTime,
}

struct Entry {
    client_id: String,
    generation: u32,
    issued: Instant,
    expires: Instant,
    expires_at: OffsetDateTime,
}

#[derive(Default)]
struct Book {
    /// Keyed by the SHA-256 of the token, so the map never holds one.
    entries: HashMap<[u8; 32], Entry>,
    last_sweep: Option<Instant>,
}

/// The tokens the server has issued and that are still live.
#[derive(Default)]
pub(crate) struct Tokens {
    book: Mutex<Book>,
}

fn key(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

impl Tokens {
    /// A new token for `client_id` at `generation` that lasts `lifetime`, and when it expires.
    /// `is_current` says whether a client still exists at a generation, so tokens of clients that
    /// were revoked or rotated are swept with the expired ones.
    pub(crate) fn issue(
        &self,
        client_id: &str,
        generation: u32,
        lifetime: Duration,
        is_current: impl Fn(&str, u32) -> bool,
    ) -> (String, OffsetDateTime) {
        let now = Instant::now();
        let token = util::new_token();
        let expires_at = OffsetDateTime::now_utc() + lifetime;
        let mut book = self.book.lock().expect("tokens lock");
        if book.last_sweep.is_none_or(|at| at + SWEEP_EVERY <= now) {
            book.entries
                .retain(|_, e| e.expires > now && is_current(&e.client_id, e.generation));
            book.last_sweep = Some(now);
        }
        let held: Vec<([u8; 32], Instant)> = book
            .entries
            .iter()
            .filter(|(_, e)| e.client_id == client_id)
            .map(|(k, e)| (*k, e.issued))
            .collect();
        if held.len() >= MAX_TOKENS_PER_CLIENT {
            let mut oldest = held;
            oldest.sort_by_key(|(_, issued)| *issued);
            let drop = oldest.len() + 1 - MAX_TOKENS_PER_CLIENT;
            for (k, _) in oldest.into_iter().take(drop) {
                book.entries.remove(&k);
            }
        }
        book.entries.insert(
            key(&token),
            Entry {
                client_id: client_id.to_owned(),
                generation,
                issued: now,
                expires: now + lifetime,
                expires_at,
            },
        );
        (token, expires_at)
    }

    /// Who `token` is for, when it is one the server issued and it has not expired. Whether its
    /// client still exists at that generation is for the caller.
    pub(crate) fn read(&self, token: &str) -> Option<Principal> {
        let now = Instant::now();
        let book = self.book.lock().expect("tokens lock");
        let entry = book.entries.get(&key(token))?;
        (entry.expires > now).then(|| Principal {
            client_id: entry.client_id.clone(),
            generation: entry.generation,
            expires_at: entry.expires_at,
        })
    }

    /// Forgets every token of a client, when it is revoked or its secret rotated.
    pub(crate) fn forget_client(&self, client_id: &str) {
        self.book
            .lock()
            .expect("tokens lock")
            .entries
            .retain(|_, e| e.client_id != client_id);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.book.lock().expect("tokens lock").entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HALF_HOUR: Duration = Duration::from_secs(30 * 60);

    fn current(_: &str, _: u32) -> bool {
        true
    }

    #[tokio::test(start_paused = true)]
    async fn a_token_is_read_back_as_its_client_until_it_expires() {
        let tokens = Tokens::default();

        let (token, expires_at) = tokens.issue("client-1", 3, HALF_HOUR, current);

        let principal = tokens.read(&token).expect("live");
        assert_eq!(principal.client_id, "client-1");
        assert_eq!(principal.generation, 3);
        assert_eq!(principal.expires_at, expires_at);
        tokio::time::advance(HALF_HOUR - Duration::from_secs(1)).await;
        assert!(tokens.read(&token).is_some());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(tokens.read(&token).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn tokens_are_64_hex_characters_that_never_repeat() {
        let tokens = Tokens::default();

        let (one, _) = tokens.issue("client-1", 1, HALF_HOUR, current);
        let (two, _) = tokens.issue("client-1", 1, HALF_HOUR, current);

        assert_eq!(one.len(), 64);
        assert!(one.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(one, two);
    }

    #[tokio::test(start_paused = true)]
    async fn a_token_the_server_did_not_issue_is_not_read() {
        let tokens = Tokens::default();
        let (token, _) = tokens.issue("client-1", 1, HALF_HOUR, current);

        assert!(tokens.read("").is_none());
        assert!(tokens.read("not a token").is_none());
        assert!(
            tokens
                .read(&token.to_lowercase().replace('a', "b"))
                .is_none()
        );
        assert!(tokens.read(&format!("{token}0")).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn the_oldest_tokens_of_a_client_are_forgotten_past_the_cap() {
        let tokens = Tokens::default();
        let (first, _) = tokens.issue("client-1", 1, HALF_HOUR, current);
        let (other, _) = tokens.issue("client-2", 1, HALF_HOUR, current);
        tokio::time::advance(Duration::from_millis(1)).await;

        let mut last = String::new();
        for _ in 0..MAX_TOKENS_PER_CLIENT {
            tokio::time::advance(Duration::from_millis(1)).await;
            last = tokens.issue("client-1", 1, HALF_HOUR, current).0;
        }

        assert!(tokens.read(&first).is_none());
        assert!(tokens.read(&last).is_some());
        assert!(tokens.read(&other).is_some());
        assert_eq!(tokens.len(), MAX_TOKENS_PER_CLIENT + 1);
    }

    #[tokio::test(start_paused = true)]
    async fn expired_tokens_and_those_of_gone_clients_are_swept_as_new_ones_are_issued() {
        let tokens = Tokens::default();
        tokens.issue("client-1", 1, Duration::from_secs(10), current);
        tokens.issue("client-2", 1, HALF_HOUR, current);
        tokens.issue("client-3", 1, HALF_HOUR, current);
        tokio::time::advance(Duration::from_secs(61)).await;

        tokens.issue("client-4", 1, HALF_HOUR, |id, _| id != "client-3");

        assert_eq!(tokens.len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn forgetting_a_client_drops_all_its_tokens_and_only_its() {
        let tokens = Tokens::default();
        let (a, _) = tokens.issue("client-1", 1, HALF_HOUR, current);
        let (b, _) = tokens.issue("client-1", 1, HALF_HOUR, current);
        let (c, _) = tokens.issue("client-2", 1, HALF_HOUR, current);

        tokens.forget_client("client-1");

        assert!(tokens.read(&a).is_none());
        assert!(tokens.read(&b).is_none());
        assert!(tokens.read(&c).is_some());
    }
}
