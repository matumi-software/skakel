//! The browser's list of servers and the rules that bound it.

use super::*;

/// The browser's entries and the rules that bound them.
#[derive(Debug, Default)]
pub(crate) struct Entries {
    seen: HashMap<EntryKey, Seen>,
    probes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct EntryKey {
    fingerprint: String,
    address: IpAddr,
    port: u16,
}

#[derive(Debug, Clone)]
pub(super) struct Seen {
    server: DiscoveredServer,
    rank: i32,
    first_seen: Instant,
    last_seen: Instant,
    /// How many probes it answered, up to the one numbered `last_probe`.
    answers: u64,
    last_probe: u64,
}

/// What counts as one address for the limits: an IPv4 address as it is, an IPv6 address as its
/// `/64`, which a host on that network owns whole.
pub(super) fn group_of(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
        v4 => v4,
    }
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
        // An address is its IPv4 address or its IPv6 `/64`: a host owns the whole `/64` and can
        // answer from any address in it.
        let group = group_of(address);
        let from_address = self
            .seen
            .keys()
            .filter(|k| group_of(k.address) == group)
            .count();
        let pool: Vec<&EntryKey> = if from_address >= MAX_ENTRIES_PER_ADDRESS {
            candidates
                .into_iter()
                .filter(|key| group_of(key.address) == group)
                .collect()
        } else if self.seen.len() >= MAX_ENTRIES {
            // From the address that holds the most.
            let mut counts: HashMap<IpAddr, Vec<&EntryKey>> = HashMap::new();
            for key in candidates {
                counts.entry(group_of(key.address)).or_default().push(key);
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
