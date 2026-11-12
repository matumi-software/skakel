//! Finds where a link's server went, as when it came back on another port after an upgrade, or its
//! machine got a new IP address. While the link cannot reach the saved address at all, and discovery
//! hears a server with the pinned certificate (or the next one) somewhere else, that is where it
//! moved.
//!
//! The fingerprint in a discovery answer is public, so anyone on the network can copy it: before
//! the move, the new address must prove it holds the certificate over a pinned handshake, so a
//! copied answer cannot draw the client away from its server. Every address heard with a trusted
//! fingerprint is a candidate, not only the one the browser lists first, so a copy cannot hide the
//! real server either; up to [`MAX_PROOFS`] are tried per search, and one that failed its proof goes
//! to the back of the queue, so the next search gets to the others.

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use url::Url;

use crate::browser::DiscoveredServer;
use crate::clock::{Clock, since};
use crate::http::authority;
use crate::pins::Pins;

/// How long an address the link moved to is not moved to again, so two addresses that both fail
/// cannot take turns.
pub(crate) const HOLD_OFF: Duration = Duration::from_secs(5 * 60);

/// How long an address has to prove it holds the pinned certificate.
pub(crate) const PROOF_TIMEOUT: Duration = Duration::from_secs(5);

/// The most addresses one search tries to prove.
pub(crate) const MAX_PROOFS: usize = 8;

/// How long the saved host name may take to resolve, when working out whether a server is on the
/// same host.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct ServerMoves {
    clock: Arc<dyn Clock>,
    searching: tokio::sync::Mutex<()>,
    times: Mutex<Times>,
}

#[derive(Default)]
struct Times {
    moved_to: HashMap<String, SystemTime>,
    failed: HashMap<String, SystemTime>,
}

impl ServerMoves {
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            searching: tokio::sync::Mutex::new(()),
            times: Mutex::new(Times::default()),
        }
    }

    /// The address to move to, or `None`. One search at a time. Each candidate, best first and at
    /// most [`MAX_PROOFS`], gets one proof (`proves`); the first that passes is the answer, and is
    /// held off from now. `servers` is every address discovery heard, not one per fingerprint.
    pub async fn find<F, Fut>(
        &self,
        saved: &Url,
        pins: &Pins,
        servers: &[DiscoveredServer],
        proves: F,
    ) -> Option<Url>
    where
        F: Fn(Url) -> Fut,
        Fut: Future<Output = bool>,
    {
        if !servers.iter().any(|s| pins.trusts(&s.fingerprint)) {
            return None;
        }
        let _searching = self.searching.lock().await;
        let now = self.clock.now();
        self.forget(now);
        let saved_host = addresses_of(saved).await;
        let candidates = {
            let times = self.times.lock().unwrap_or_else(|e| e.into_inner());
            candidates(
                saved,
                pins,
                servers,
                &saved_host,
                &|a| times.moved_to.contains_key(a),
                &|a| times.failed.get(a).copied(),
            )
        };
        for url in candidates {
            let key = authority(&url);
            if proves(url.clone()).await {
                let mut times = self.times.lock().unwrap_or_else(|e| e.into_inner());
                times.moved_to.insert(key.clone(), now);
                times.failed.remove(&key);
                return Some(url);
            }
            self.times
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .failed
                .insert(key, self.clock.now());
        }
        None
    }

    /// Drops what is older than [`HOLD_OFF`].
    fn forget(&self, now: SystemTime) {
        let mut times = self.times.lock().unwrap_or_else(|e| e.into_inner());
        times.moved_to.retain(|_, at| since(now, *at) < HOLD_OFF);
        times.failed.retain(|_, at| since(now, *at) < HOLD_OFF);
    }
}

/// The addresses a link at `saved` could move to, best first and at most [`MAX_PROOFS`]: where
/// discovery hears a server with a certificate it trusts, other than the saved address. One on the
/// saved host (`saved_host`) on another port comes first, and keeps the saved host name; then any
/// other, in the order discovery has them. One that failed a proof (`failed_at`) comes after those
/// that did not, the longest ago first. An address moved to a little while ago is `held_off`.
pub(crate) fn candidates(
    saved: &Url,
    pins: &Pins,
    servers: &[DiscoveredServer],
    saved_host: &[IpAddr],
    held_off: &dyn Fn(&str) -> bool,
    failed_at: &dyn Fn(&str) -> Option<SystemTime>,
) -> Vec<Url> {
    let saved_authority = authority(saved);
    let mut seen: Vec<String> = Vec::new();
    let mut all: Vec<(bool, Url, Option<SystemTime>)> = Vec::new();
    for server in servers.iter().filter(|s| pins.trusts(&s.fingerprint)) {
        let same_host = saved_host.contains(&plain(server.address));
        let url = if same_host {
            let mut url = saved.clone();
            let _ = url.set_port(Some(server.port));
            url
        } else {
            server.url()
        };
        let key = authority(&url);
        if key == saved_authority || held_off(&key) || seen.contains(&key) {
            continue;
        }
        seen.push(key.clone());
        all.push((same_host, url, failed_at(&key)));
    }
    // Stable sorts: the order discovery has them is kept within a rank.
    all.sort_by_key(|a| (a.2.is_some(), !a.0, a.2));
    all.into_iter()
        .take(MAX_PROOFS)
        .map(|(_, url, _)| url)
        .collect()
}

fn plain(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    }
}

/// The addresses the saved host stands for: itself when it is one, otherwise what its name resolves
/// to now, or none.
async fn addresses_of(saved: &Url) -> Vec<IpAddr> {
    match saved.host() {
        Some(url::Host::Ipv4(address)) => vec![plain(IpAddr::V4(address))],
        Some(url::Host::Ipv6(address)) => vec![plain(IpAddr::V6(address))],
        Some(url::Host::Domain(name)) => {
            let port = saved.port_or_known_default().unwrap_or(443);
            let lookup =
                tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host((name, port))).await;
            match lookup {
                Ok(Ok(found)) => found.map(|a| plain(a.ip())).collect(),
                Ok(Err(error)) => {
                    log::info!(
                        "Could not resolve {name} to compare it with the servers on the network: {error}"
                    );
                    Vec::new()
                }
                Err(_) => {
                    log::info!(
                        "Could not resolve {name} to compare it with the servers on the network: timed out"
                    );
                    Vec::new()
                }
            }
        }
        None => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::SystemClock;
    use skakel_protocol::SkakelApp;
    use std::net::Ipv4Addr;

    fn fingerprint(pair: &str) -> String {
        vec![pair; 32].join(":")
    }

    fn found(address: [u8; 4], port: u16, fp: &str) -> DiscoveredServer {
        DiscoveredServer {
            name: "bench".into(),
            address: IpAddr::V4(Ipv4Addr::from(address)),
            port,
            fingerprint: fingerprint(fp),
            app: SkakelApp {
                id: "test-app".into(),
                version: "1".into(),
            },
            versions: vec![2],
            other_endpoints: Vec::new(),
        }
    }

    fn saved() -> Url {
        Url::parse("https://pi-lab:5240/").unwrap()
    }

    fn pins() -> Pins {
        Pins::with_next(&fingerprint("AB"), Some(&fingerprint("CD"))).unwrap()
    }

    fn none(_: &str) -> bool {
        false
    }

    fn never(_: &str) -> Option<SystemTime> {
        None
    }

    fn texts(urls: Vec<Url>) -> Vec<String> {
        urls.into_iter().map(|u| u.to_string()).collect()
    }

    #[test]
    fn candidates_are_servers_with_a_trusted_fingerprint_other_than_the_saved_address() {
        let servers = [
            found([10, 0, 0, 5], 5240, "AB"),
            found([10, 0, 0, 6], 5240, "CD"),
            found([10, 0, 0, 7], 5240, "EF"),
            found([10, 0, 0, 8], 5240, "AB"),
        ];
        let saved = Url::parse("https://10.0.0.5:5240/").unwrap();

        let urls = candidates(
            &saved,
            &pins(),
            &servers,
            &[IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))],
            &none,
            &never,
        );

        assert_eq!(
            texts(urls),
            ["https://10.0.0.6:5240/", "https://10.0.0.8:5240/"]
        );
    }

    #[test]
    fn a_server_on_the_saved_host_on_another_port_comes_first_and_keeps_the_host_name() {
        let servers = [
            found([10, 0, 0, 9], 5240, "AB"),
            found([10, 0, 0, 5], 6000, "AB"),
        ];

        let urls = candidates(
            &saved(),
            &pins(),
            &servers,
            &[IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))],
            &none,
            &never,
        );

        assert_eq!(
            texts(urls),
            ["https://pi-lab:6000/", "https://10.0.0.9:5240/"]
        );
    }

    #[test]
    fn an_address_that_failed_its_proof_goes_after_those_that_did_not_the_longest_ago_first() {
        let servers = [
            found([10, 0, 0, 1], 1, "AB"),
            found([10, 0, 0, 2], 1, "AB"),
            found([10, 0, 0, 3], 1, "AB"),
        ];
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let failed = |a: &str| match a {
            "10.0.0.1:1" => Some(base + Duration::from_secs(20)),
            "10.0.0.2:1" => Some(base),
            _ => None,
        };

        let urls = candidates(&saved(), &pins(), &servers, &[], &none, &failed);

        assert_eq!(
            texts(urls),
            [
                "https://10.0.0.3:1/",
                "https://10.0.0.2:1/",
                "https://10.0.0.1:1/"
            ]
        );
    }

    #[test]
    fn a_held_off_address_and_a_repeated_one_are_left_out() {
        let servers = [
            found([10, 0, 0, 1], 1, "AB"),
            found([10, 0, 0, 1], 1, "CD"),
            found([10, 0, 0, 2], 1, "AB"),
        ];

        let urls = candidates(
            &saved(),
            &pins(),
            &servers,
            &[],
            &|a| a == "10.0.0.2:1",
            &never,
        );

        assert_eq!(texts(urls), ["https://10.0.0.1:1/"]);
    }

    #[test]
    fn at_most_eight_candidates_are_tried() {
        let servers: Vec<_> = (1..=20u8).map(|i| found([10, 0, 0, i], 1, "AB")).collect();

        assert_eq!(
            candidates(&saved(), &pins(), &servers, &[], &none, &never).len(),
            MAX_PROOFS
        );
    }

    #[tokio::test]
    async fn find_moves_to_the_first_address_that_proves_it_and_holds_it_off() {
        let moves = ServerMoves::new(Arc::new(SystemClock));
        let servers = [found([10, 0, 0, 1], 1, "AB"), found([10, 0, 0, 2], 1, "AB")];
        let saved = Url::parse("https://10.0.0.9:5240/").unwrap();
        let tried = Mutex::new(Vec::new());

        let moved = moves
            .find(&saved, &pins(), &servers, |url| {
                tried.lock().unwrap().push(url.to_string());
                let proven = url.host_str() == Some("10.0.0.2");
                async move { proven }
            })
            .await;

        assert_eq!(moved.unwrap().as_str(), "https://10.0.0.2:1/");
        assert_eq!(
            *tried.lock().unwrap(),
            ["https://10.0.0.1:1/", "https://10.0.0.2:1/"]
        );

        // Held off now: the next search tries the one that failed, and not the one moved to.
        tried.lock().unwrap().clear();
        let again = moves
            .find(&saved, &pins(), &servers, |url| {
                tried.lock().unwrap().push(url.to_string());
                async { false }
            })
            .await;

        assert!(again.is_none());
        assert_eq!(*tried.lock().unwrap(), ["https://10.0.0.1:1/"]);
    }

    #[tokio::test]
    async fn find_does_nothing_when_no_server_has_a_trusted_fingerprint() {
        let moves = ServerMoves::new(Arc::new(SystemClock));

        let moved = moves
            .find(
                &saved(),
                &pins(),
                &[found([10, 0, 0, 1], 1, "EF")],
                |_| async { true },
            )
            .await;

        assert!(moved.is_none());
    }
}
