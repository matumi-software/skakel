//! Finds an app's servers on the local network: broadcasts a probe every ten seconds to the app's
//! port on every IPv4 network this machine is on, and lists the servers that answer.
//!
//! Anyone on the network can answer anything, so what it keeps is bounded by the limits in the
//! protocol: answers only shortly after a probe, at most 64 entries and 8 from one address,
//! fingerprints that are really fingerprints, short names, and entries that go when they stop
//! answering.
//!
//! Entries are told apart by fingerprint, address and port, so an answer that copies another
//! server's name or fingerprint sits beside the real one instead of replacing it. The list shows one
//! entry per fingerprint: the address that answered first, on the best network. Every other address
//! that answered with the same fingerprint is in [`DiscoveredServer::other_endpoints`], so an app can
//! warn that several addresses claim one certificate; only a pinned connection tells which holds it.
//!
//! One browser serves every link of an app; pass it to each in
//! [`ClientOptions::browser`](crate::ClientOptions::browser).

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use reqwest::Url;
use skakel_discovery::{
    ANSWER_WINDOW, ENTRY_LIFETIME, MAX_ENTRIES, MAX_ENTRIES_PER_ADDRESS, PROBE_INTERVAL,
    create_probe, try_parse_answer,
};
use skakel_protocol::SkakelApp;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::http::PinsFn;
use crate::info::pick_version;

/// A server that answered a discovery probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredServer {
    /// The name people know it by; its address when it gave none.
    pub name: String,
    /// Where the answer came from, which is where to reach it.
    pub address: IpAddr,
    /// Its HTTPS port.
    pub port: u16,
    /// Its certificate's fingerprint, in colon form. Anyone on the network can copy it; pairing and
    /// pinning are what prove it.
    pub fingerprint: String,
    /// The app it belongs to.
    pub app: SkakelApp,
    /// The protocol versions it speaks.
    pub versions: Vec<i32>,
    /// The other addresses and ports that answered with this fingerprint, best first. A server on
    /// several networks answers on each; a machine that copied the fingerprint shows up here too, and
    /// only a pinned connection tells them apart. More than one is reason to say that several
    /// addresses claim this server's certificate. [`Browser::servers`] fills it; empty otherwise.
    pub other_endpoints: Vec<SocketAddr>,
}

impl DiscoveredServer {
    /// Its HTTPS address, such as `https://192.168.1.20:5240/`.
    pub fn url(&self) -> Url {
        let host = match self.address {
            IpAddr::V4(address) => address.to_string(),
            IpAddr::V6(address) => format!("[{address}]"),
        };
        Url::parse(&format!("https://{host}:{}/", self.port))
            .expect("an address and a port make a URL")
    }

    /// The highest protocol version it and this client both speak, or `None` when there is none.
    pub fn version(&self) -> Option<u32> {
        pick_version(&self.versions)
    }
}

/// How a browser probes. Without options it broadcasts every ten seconds on every IPv4 network.
#[derive(Debug, Clone)]
pub struct BrowserOptions {
    /// The app's port number: servers answer probes on UDP at the number their HTTPS listens on.
    pub port: u16,
    /// The app ids whose servers this app can use. Answers from other apps are dropped. `None`
    /// keeps every app's.
    pub app_ids: Option<Vec<String>>,
    /// Where to send each probe instead of broadcasting, such as a server's address that was entered
    /// by hand, or loopback in a test.
    pub probe_targets: Option<Vec<SocketAddr>>,
    /// How often to probe. Ten seconds unless set; an entry that misses three probes in a row, and a
    /// little more, is gone.
    pub probe_interval: Duration,
}

impl BrowserOptions {
    /// Options for a browser on the app's port.
    pub fn new(port: u16) -> Self {
        Self {
            port,
            app_ids: None,
            probe_targets: None,
            probe_interval: PROBE_INTERVAL,
        }
    }
}

/// The browser's entries and the rules that bound them.
#[derive(Debug, Default)]
pub(crate) struct Entries {
    seen: HashMap<EntryKey, Seen>,
    probes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct EntryKey {
    fingerprint: String,
    address: IpAddr,
    port: u16,
}

#[derive(Debug, Clone)]
struct Seen {
    server: DiscoveredServer,
    rank: i32,
    first_seen: Instant,
    last_seen: Instant,
    /// How many probes it answered, up to the one numbered `last_probe`.
    answers: u64,
    last_probe: u64,
}

impl Entries {
    /// A probe went out.
    pub fn probed(&mut self) {
        self.probes += 1;
    }

    /// Keeps or refreshes an entry. When one address already holds its share, one of its entries
    /// goes to make room. When the whole list is full, one goes from the address holding the most,
    /// so a flood from one address pushes out its own entries and not other servers'. The one that
    /// goes is the one that answered the fewest probes, then the stalest, and never one a running
    /// link has pinned; when only those are left, the new answer is dropped instead.
    ///
    /// False when the answer was dropped.
    pub fn add(
        &mut self,
        server: DiscoveredServer,
        rank: i32,
        now: Instant,
        is_protected: &dyn Fn(&str) -> bool,
    ) -> bool {
        let key = EntryKey {
            fingerprint: server.fingerprint.clone(),
            address: server.address,
            port: server.port,
        };
        let probes = self.probes;
        if let Some(seen) = self.seen.get_mut(&key) {
            seen.answers = if seen.last_probe == probes {
                seen.answers
            } else {
                seen.answers + 1
            };
            seen.server = server;
            seen.rank = rank;
            seen.last_seen = now;
            seen.last_probe = probes;
            return true;
        }
        if !self.make_room(server.address, is_protected) {
            return false;
        }
        self.seen.insert(
            key,
            Seen {
                server,
                rank,
                first_seen: now,
                last_seen: now,
                answers: 1,
                last_probe: probes,
            },
        );
        true
    }

    /// Drops the entries that stopped answering. True when any went.
    pub fn sweep(&mut self, now: Instant, lifetime: Duration) -> bool {
        let before = self.seen.len();
        self.seen
            .retain(|_, seen| now.saturating_duration_since(seen.last_seen) < lifetime);
        self.seen.len() != before
    }

    pub fn clear(&mut self) -> bool {
        let any = !self.seen.is_empty();
        self.seen.clear();
        any
    }

    /// Makes room for an entry from `address`: false when every entry that could go is protected.
    fn make_room(&mut self, address: IpAddr, is_protected: &dyn Fn(&str) -> bool) -> bool {
        let candidates: Vec<&EntryKey> = self
            .seen
            .keys()
            .filter(|key| !is_protected(&key.fingerprint))
            .collect();
        let from_address = self.seen.keys().filter(|k| k.address == address).count();
        let pool: Vec<&EntryKey> = if from_address >= MAX_ENTRIES_PER_ADDRESS {
            candidates
                .into_iter()
                .filter(|key| key.address == address)
                .collect()
        } else if self.seen.len() >= MAX_ENTRIES {
            // From the address that holds the most.
            let mut counts: HashMap<IpAddr, Vec<&EntryKey>> = HashMap::new();
            for key in candidates {
                counts.entry(key.address).or_default().push(key);
            }
            counts
                .into_values()
                .max_by(|a, b| a.len().cmp(&b.len()))
                .unwrap_or_default()
        } else {
            return true;
        };
        let victim = pool
            .into_iter()
            .min_by_key(|key| {
                let seen = &self.seen[*key];
                (seen.answers, seen.last_seen)
            })
            .cloned();
        match victim {
            Some(key) => {
                self.seen.remove(&key);
                true
            }
            None => false,
        }
    }

    /// Best network first, then the longest standing, so a newcomer does not take an older entry's
    /// place.
    fn ordered<'a>(seen: impl Iterator<Item = &'a Seen>) -> Vec<&'a Seen> {
        let mut all: Vec<&Seen> = seen.collect();
        all.sort_by(|a, b| {
            (
                a.rank,
                a.first_seen,
                a.server.address.to_string(),
                a.server.port,
            )
                .cmp(&(
                    b.rank,
                    b.first_seen,
                    b.server.address.to_string(),
                    b.server.port,
                ))
        });
        all
    }

    /// One entry per fingerprint, sorted by name: the address that answered first on the best
    /// network, with every other address that answered with the same fingerprint beside it.
    pub fn snapshot(&self) -> Vec<DiscoveredServer> {
        let mut groups: HashMap<&str, Vec<&Seen>> = HashMap::new();
        for seen in self.seen.values() {
            groups
                .entry(&seen.server.fingerprint)
                .or_default()
                .push(seen);
        }
        let mut servers: Vec<DiscoveredServer> = groups
            .into_values()
            .map(|group| {
                let ordered = Self::ordered(group.into_iter());
                let mut server = ordered[0].server.clone();
                server.other_endpoints = ordered[1..]
                    .iter()
                    .map(|s| SocketAddr::new(s.server.address, s.server.port))
                    .collect();
                server
            })
            .collect();
        servers.sort_by(|a, b| {
            (a.name.to_lowercase(), &a.fingerprint).cmp(&(b.name.to_lowercase(), &b.fingerprint))
        });
        servers
    }

    /// Every address and port that answered, one entry each, the best network and the longest
    /// standing first.
    pub fn all(&self) -> Vec<DiscoveredServer> {
        Self::ordered(self.seen.values())
            .into_iter()
            .map(|s| s.server.clone())
            .collect()
    }
}

struct State {
    entries: Entries,
    probed_at: Option<Instant>,
    published: Vec<DiscoveredServer>,
}

struct Running {
    stop: CancellationToken,
    socket: Arc<UdpSocket>,
}

struct Inner {
    options: BrowserOptions,
    app_ids: Option<HashSet<String>>,
    state: Mutex<State>,
    changes: watch::Sender<Vec<DiscoveredServer>>,
    protected: Mutex<Vec<(u64, PinsFn)>>,
    next_protection: Mutex<u64>,
    running: Mutex<Option<Running>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let Some(running) = self.running.get_mut().ok().and_then(Option::take) {
            running.stop.cancel();
        }
    }
}

/// Finds an app's servers on the local network. Cloning gives another handle to the same browser.
/// Without [`stop`](Self::stop), probing ends when the last handle is dropped.
#[derive(Clone)]
pub struct Browser {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Browser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Browser")
            .field("port", &self.inner.options.port)
            .finish_non_exhaustive()
    }
}

/// Keeps the entries of servers with these pins from being pushed out to make room, until dropped.
pub(crate) struct Protection {
    inner: Weak<Inner>,
    id: u64,
}

impl Drop for Protection {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.upgrade() {
            inner
                .protected
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|(id, _)| *id != self.id);
        }
    }
}

impl Browser {
    /// A browser for the servers of the given apps, on the app's port. Call
    /// [`start`](Self::start) to begin.
    pub fn new(port: u16, app_ids: Option<Vec<String>>) -> Self {
        Self::with_options(BrowserOptions {
            app_ids,
            ..BrowserOptions::new(port)
        })
    }

    /// A browser with its own probe targets and interval.
    pub fn with_options(options: BrowserOptions) -> Self {
        let (changes, _) = watch::channel(Vec::new());
        Self {
            inner: Arc::new(Inner {
                app_ids: options
                    .app_ids
                    .as_ref()
                    .map(|ids| ids.iter().cloned().collect()),
                options,
                state: Mutex::new(State {
                    entries: Entries::default(),
                    probed_at: None,
                    published: Vec::new(),
                }),
                changes,
                protected: Mutex::new(Vec::new()),
                next_protection: Mutex::new(0),
                running: Mutex::new(None),
            }),
        }
    }

    /// One entry per fingerprint, sorted by name: the address that answered first on the best
    /// network, with every other address that answered with the same fingerprint in
    /// [`DiscoveredServer::other_endpoints`].
    pub fn servers(&self) -> Vec<DiscoveredServer> {
        self.inner.state().entries.snapshot()
    }

    /// The list as it changes. A server appears, changes or goes away; a slow reader gets the latest
    /// list, not every one in between.
    pub fn watch(&self) -> watch::Receiver<Vec<DiscoveredServer>> {
        self.inner.changes.subscribe()
    }

    /// Every address and port that answered, one entry each, the best network and the longest
    /// standing first. What a link looks through to follow its server.
    pub fn entries(&self) -> Vec<DiscoveredServer> {
        self.inner.state().entries.all()
    }

    /// True while probes go out.
    pub fn is_browsing(&self) -> bool {
        self.inner.running().is_some()
    }

    /// Starts listening and sends the first probe at once. Starting a started browser does nothing.
    pub async fn start(&self) -> io::Result<()> {
        if self.is_browsing() {
            return Ok(());
        }
        let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).await?;
        socket.set_broadcast(true)?;
        let socket = Arc::new(socket);
        let stop = CancellationToken::new();
        {
            let mut running = self.inner.running();
            if running.is_some() {
                return Ok(());
            }
            *running = Some(Running {
                stop: stop.clone(),
                socket: socket.clone(),
            });
        }
        tokio::spawn(listen(Arc::downgrade(&self.inner), socket, stop.clone()));
        tokio::spawn(probe_every(Arc::downgrade(&self.inner), stop));
        self.probe_now().await;
        Ok(())
    }

    /// Stops probing and empties the list.
    pub fn stop(&self) {
        if let Some(running) = self.inner.running().take() {
            running.stop.cancel();
        }
        let mut state = self.inner.state();
        state.probed_at = None;
        if state.entries.clear() {
            self.inner.publish(&mut state);
        }
    }

    /// Sends a probe now, and takes answers for the next few seconds. A probe goes out every
    /// [`BrowserOptions::probe_interval`] besides.
    pub async fn probe_now(&self) {
        probe(&self.inner).await;
    }

    /// Keeps the entries of servers with these pins from being pushed out to make room. A link does
    /// this while it lives.
    pub(crate) fn protect(&self, pins: PinsFn) -> Protection {
        let mut next = self
            .inner
            .next_protection
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *next += 1;
        let id = *next;
        self.inner
            .protected
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((id, pins));
        Protection {
            inner: Arc::downgrade(&self.inner),
            id,
        }
    }

    /// An answer from the network, as if a probe had just been answered. For a test that stands in
    /// for the network.
    #[doc(hidden)]
    pub fn add_for_test(&self, server: DiscoveredServer, rank: i32) {
        self.inner.add(server, rank, Instant::now());
    }
}

impl Inner {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn running(&self) -> std::sync::MutexGuard<'_, Option<Running>> {
        self.running.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn is_protected(&self, fingerprint: &str) -> bool {
        self.protected
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|(_, pins)| pins().trusts(fingerprint))
    }

    /// Queues the current list when it differs from the last one published, with the state held,
    /// so lists leave in the order the changes happened.
    fn publish(&self, state: &mut State) {
        let snapshot = state.entries.snapshot();
        if snapshot != state.published {
            state.published = snapshot.clone();
            self.changes.send_replace(snapshot);
        }
    }

    fn add(&self, server: DiscoveredServer, rank: i32, now: Instant) {
        if self
            .app_ids
            .as_ref()
            .is_some_and(|ids| !ids.contains(&server.app.id))
        {
            return;
        }
        let mut state = self.state();
        if state
            .entries
            .add(server, rank, now, &|fp| self.is_protected(fp))
        {
            self.publish(&mut state);
        }
    }

    /// An answer from the network: taken only within a few seconds of a probe, as answers to it.
    fn answered(&self, server: DiscoveredServer, rank: i32) {
        let now = Instant::now();
        {
            let state = self.state();
            match state.probed_at {
                Some(at) if now.saturating_duration_since(at) <= ANSWER_WINDOW => {}
                _ => return,
            }
        }
        self.add(server, rank, now);
    }

    fn sweep(&self) {
        let lifetime = self
            .options
            .probe_interval
            .mul_f64(3.5)
            .max(Duration::from_millis(1));
        let lifetime = if self.options.probe_interval == PROBE_INTERVAL {
            ENTRY_LIFETIME
        } else {
            lifetime
        };
        let mut state = self.state();
        if state.entries.sweep(Instant::now(), lifetime) {
            self.publish(&mut state);
        }
    }
}

async fn probe(inner: &Inner) {
    let socket = {
        let Some(running) = inner.running().as_ref().map(|r| r.socket.clone()) else {
            return;
        };
        let mut state = inner.state();
        state.entries.probed();
        state.probed_at = Some(Instant::now());
        running
    };
    let probe = create_probe();
    let targets = inner
        .options
        .probe_targets
        .clone()
        .unwrap_or_else(|| broadcast_targets(inner.options.port));
    for target in targets {
        // That network is down or refuses broadcasts; the others still get the probe.
        let _ = socket.send_to(&probe, target).await;
    }
}

async fn probe_every(inner: Weak<Inner>, stop: CancellationToken) {
    let interval = match inner.upgrade() {
        Some(inner) => inner.options.probe_interval,
        None => return,
    };
    loop {
        tokio::select! {
            () = stop.cancelled() => return,
            () = tokio::time::sleep(interval) => {}
        }
        let Some(inner) = inner.upgrade() else {
            return;
        };
        inner.sweep();
        probe(&inner).await;
    }
}

async fn listen(inner: Weak<Inner>, socket: Arc<UdpSocket>, stop: CancellationToken) {
    let mut buffer = [0u8; 2048];
    let mut networks = Networks::default();
    loop {
        let received = tokio::select! {
            () = stop.cancelled() => return,
            received = socket.recv_from(&mut buffer) => received,
        };
        let (length, from) = match received {
            Ok(received) => received,
            Err(error) => {
                // Windows reports a probe nobody received on the next receive. Keep listening, but
                // not in a tight loop if the error is not about one datagram.
                if error.kind() != io::ErrorKind::ConnectionReset {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                continue;
            }
        };
        let Some(inner) = inner.upgrade() else {
            return;
        };
        let Some(answer) = try_parse_answer(&buffer[..length]) else {
            continue;
        };
        let address = match from.ip() {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
            v4 => v4,
        };
        let name = if answer.name.is_empty() {
            address.to_string()
        } else {
            answer.name
        };
        let rank = networks.rank(address);
        inner.answered(
            DiscoveredServer {
                name,
                address,
                port: answer.port,
                fingerprint: answer.fingerprint,
                app: answer.app,
                versions: answer.versions,
                other_endpoints: Vec::new(),
            },
            rank,
        );
    }
}

/// The limited broadcast address and each IPv4 network's own broadcast address. On a machine with
/// several networks the limited one only leaves through one of them.
fn broadcast_targets(port: u16) -> Vec<SocketAddr> {
    let mut targets = vec![Ipv4Addr::BROADCAST];
    for interface in if_addrs::get_if_addrs().unwrap_or_default() {
        if interface.is_loopback() {
            continue;
        }
        if let if_addrs::IfAddr::V4(v4) = &interface.addr {
            let broadcast = v4
                .broadcast
                .unwrap_or_else(|| Ipv4Addr::from(u32::from(v4.ip) | !u32::from(v4.netmask)));
            if v4.netmask != Ipv4Addr::BROADCAST && !targets.contains(&broadcast) {
                targets.push(broadcast);
            }
        }
    }
    targets
        .into_iter()
        .map(|address| SocketAddr::new(IpAddr::V4(address), port))
        .collect()
}

/// Prefers an address on a wired or wireless network over one on a virtual network, such as a
/// Hyper-V switch or Docker's bridge, when a server answers on both. The networks are read at most
/// once every ten seconds, not for every answer.
#[derive(Default)]
struct Networks {
    physical: Vec<(Ipv4Addr, Ipv4Addr)>,
    until: Option<Instant>,
}

impl Networks {
    const REREAD: Duration = Duration::from_secs(10);

    fn rank(&mut self, address: IpAddr) -> i32 {
        if self.until.is_none_or(|until| Instant::now() >= until) {
            self.physical = if_addrs::get_if_addrs()
                .unwrap_or_default()
                .into_iter()
                .filter(|i| !i.is_loopback() && !is_virtual(&i.name))
                .filter_map(|i| match i.addr {
                    if_addrs::IfAddr::V4(v4) => Some((v4.ip, v4.netmask)),
                    if_addrs::IfAddr::V6(_) => None,
                })
                .collect();
            self.until = Some(Instant::now() + Self::REREAD);
        }
        let IpAddr::V4(address) = address else {
            return 1;
        };
        let same = |(ip, mask): &(Ipv4Addr, Ipv4Addr)| {
            (u32::from(address) & u32::from(*mask)) == (u32::from(*ip) & u32::from(*mask))
        };
        if self.physical.iter().any(same) { 0 } else { 1 }
    }
}

/// An interface whose name says it is a virtual network.
fn is_virtual(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "virtual",
        "hyper-v",
        "vethernet",
        "docker",
        "vmware",
        "vbox",
        "wsl",
        "veth",
        "br-",
        "tailscale",
    ]
    .iter()
    .any(|word| name.contains(word))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint(pair: &str) -> String {
        vec![pair; 32].join(":")
    }

    fn server(name: &str, address: [u8; 4], port: u16, fp: &str) -> DiscoveredServer {
        DiscoveredServer {
            name: name.into(),
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

    fn none_protected(_: &str) -> bool {
        false
    }

    fn at(base: Instant, seconds: u64) -> Instant {
        base + Duration::from_secs(seconds)
    }

    #[test]
    fn the_list_has_one_entry_per_fingerprint_with_the_other_addresses_beside_it() {
        let base = Instant::now();
        let mut entries = Entries::default();
        entries.add(
            server("bench", [10, 0, 0, 5], 5240, "AB"),
            0,
            base,
            &none_protected,
        );
        entries.add(
            server("bench", [10, 0, 1, 5], 5240, "AB"),
            1,
            at(base, 1),
            &none_protected,
        );
        entries.add(
            server("bench", [10, 0, 0, 9], 5240, "AB"),
            0,
            at(base, 2),
            &none_protected,
        );

        let list = entries.snapshot();

        assert_eq!(list.len(), 1);
        assert_eq!(list[0].address, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)));
        assert_eq!(
            list[0].other_endpoints,
            [
                "10.0.0.9:5240".parse::<SocketAddr>().unwrap(),
                "10.0.1.5:5240".parse().unwrap()
            ]
        );
        assert_eq!(entries.all().len(), 3);
    }

    #[test]
    fn a_copy_of_a_fingerprint_sits_beside_the_real_server_and_never_replaces_it() {
        let base = Instant::now();
        let mut entries = Entries::default();
        entries.add(
            server("real", [10, 0, 0, 5], 5240, "AB"),
            0,
            base,
            &none_protected,
        );
        entries.add(
            server("fake", [10, 0, 0, 66], 5240, "AB"),
            0,
            at(base, 1),
            &none_protected,
        );

        let list = entries.snapshot();

        assert_eq!(list[0].name, "real");
        assert_eq!(list[0].other_endpoints.len(), 1);
    }

    #[test]
    fn servers_are_sorted_by_name_without_regard_to_case() {
        let base = Instant::now();
        let mut entries = Entries::default();
        entries.add(
            server("beta", [10, 0, 0, 1], 1, "01"),
            0,
            base,
            &none_protected,
        );
        entries.add(
            server("Alpha", [10, 0, 0, 2], 1, "02"),
            0,
            base,
            &none_protected,
        );
        entries.add(
            server("gamma", [10, 0, 0, 3], 1, "03"),
            0,
            base,
            &none_protected,
        );

        let names: Vec<String> = entries.snapshot().into_iter().map(|s| s.name).collect();

        assert_eq!(names, ["Alpha", "beta", "gamma"]);
    }

    #[test]
    fn an_address_keeps_at_most_eight_entries_and_pushes_out_its_own() {
        let base = Instant::now();
        let mut entries = Entries::default();
        for i in 0..9u8 {
            entries.probed();
            entries.add(
                server("x", [10, 0, 0, 5], 5000 + u16::from(i), &format!("{i:02X}")),
                0,
                at(base, u64::from(i)),
                &none_protected,
            );
        }
        entries.add(
            server("other", [10, 0, 0, 6], 1, "EE"),
            0,
            at(base, 20),
            &none_protected,
        );

        let all = entries.all();

        assert_eq!(
            all.iter()
                .filter(|s| s.address == IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)))
                .count(),
            8
        );
        assert!(all.iter().any(|s| s.name == "other"));
    }

    #[test]
    fn a_full_list_makes_room_from_the_address_that_holds_the_most() {
        let base = Instant::now();
        let mut entries = Entries::default();
        for i in 0..MAX_ENTRIES {
            // Eight to an address.
            let address = [10, 0, (i / 8) as u8, 1];
            entries.add(
                server(
                    "x",
                    address,
                    1 + (i % 8) as u16,
                    &format!("{:02X}", i % 256),
                ),
                0,
                base,
                &none_protected,
            );
            // Fingerprints repeat past 255; the port tells the entries apart.
        }
        assert_eq!(entries.all().len(), MAX_ENTRIES);

        let added = entries.add(
            server("new", [10, 9, 9, 9], 1, "FE"),
            0,
            at(base, 1),
            &none_protected,
        );

        assert!(added);
        assert_eq!(entries.all().len(), MAX_ENTRIES);
        assert!(entries.all().iter().any(|s| s.name == "new"));
    }

    #[test]
    fn an_entry_a_running_link_pinned_is_never_pushed_out() {
        let base = Instant::now();
        let mut entries = Entries::default();
        let pinned = fingerprint("AB");
        let protect = |fp: &str| fp == pinned;
        for i in 0..8u16 {
            entries.add(
                server("x", [10, 0, 0, 5], 5000 + i, "AB"),
                0,
                base,
                &protect,
            );
        }

        let added = entries.add(
            server("y", [10, 0, 0, 5], 6000, "CD"),
            0,
            at(base, 1),
            &protect,
        );

        assert!(
            !added,
            "only protected entries were left to push out, so the new answer is dropped"
        );
        assert_eq!(entries.all().len(), 8);
    }

    #[test]
    fn the_entry_that_answered_the_fewest_probes_goes_first() {
        let base = Instant::now();
        let mut entries = Entries::default();
        for i in 0..8u16 {
            entries.probed();
            entries.add(
                server("x", [10, 0, 0, 5], 5000 + i, "AB"),
                0,
                at(base, u64::from(i)),
                &none_protected,
            );
        }
        // Port 5003 answers the next probe too, so it has answered more than the rest.
        entries.probed();
        entries.add(
            server("x", [10, 0, 0, 5], 5003, "AB"),
            0,
            at(base, 9),
            &none_protected,
        );

        entries.add(
            server("y", [10, 0, 0, 5], 6000, "CD"),
            0,
            at(base, 10),
            &none_protected,
        );

        let ports: Vec<u16> = entries.all().iter().map(|s| s.port).collect();
        assert!(ports.contains(&5003));
        assert!(ports.contains(&6000));
        assert!(
            !ports.contains(&5000),
            "the stalest of those that answered once went"
        );
    }

    #[test]
    fn an_entry_that_stops_answering_expires() {
        let base = Instant::now();
        let mut entries = Entries::default();
        entries.add(
            server("x", [10, 0, 0, 1], 1, "AB"),
            0,
            base,
            &none_protected,
        );

        assert!(!entries.sweep(at(base, 34), ENTRY_LIFETIME));
        assert!(entries.sweep(at(base, 35), ENTRY_LIFETIME));
        assert!(entries.all().is_empty());
    }

    #[test]
    fn rank_prefers_a_physical_network() {
        let base = Instant::now();
        let mut entries = Entries::default();
        entries.add(
            server("v", [172, 17, 0, 2], 1, "AB"),
            1,
            base,
            &none_protected,
        );
        entries.add(
            server("p", [192, 168, 1, 2], 1, "AB"),
            0,
            at(base, 5),
            &none_protected,
        );

        assert_eq!(
            entries.snapshot()[0].address,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))
        );
    }

    #[test]
    fn virtual_networks_are_told_by_their_names() {
        assert!(is_virtual("vEthernet (WSL)"));
        assert!(is_virtual("docker0"));
        assert!(!is_virtual("Ethernet"));
        assert!(!is_virtual("Wi-Fi"));
    }

    #[test]
    fn a_server_has_a_url_and_a_version() {
        let found = server("x", [192, 168, 1, 20], 5240, "AB");

        assert_eq!(found.url().as_str(), "https://192.168.1.20:5240/");
        assert_eq!(found.version(), Some(2));
    }

    #[test]
    fn broadcast_targets_start_with_the_limited_broadcast_address() {
        let targets = broadcast_targets(5240);

        assert_eq!(
            targets[0],
            "255.255.255.255:5240".parse::<SocketAddr>().unwrap()
        );
        assert!(targets.iter().all(|t| t.port() == 5240));
    }
}
