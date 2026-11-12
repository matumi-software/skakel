//! Which networks to probe on, and which interfaces are not real ones.

use super::*;

/// The limited broadcast address and each IPv4 network's own broadcast address. On a machine with
/// several networks the limited one only leaves through one of them.
pub(super) fn broadcast_targets(port: u16) -> Vec<SocketAddr> {
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
pub(super) struct Networks {
    physical: Vec<(Ipv4Addr, Ipv4Addr)>,
    until: Option<Instant>,
}

impl Networks {
    const REREAD: Duration = Duration::from_secs(10);

    pub(super) fn rank(&mut self, address: IpAddr) -> i32 {
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
pub(super) fn is_virtual(name: &str) -> bool {
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
