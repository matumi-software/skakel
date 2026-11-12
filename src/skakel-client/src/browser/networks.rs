//! Which networks to probe on, and which interfaces are not real ones.

use std::net::Ipv6Addr;

use super::*;

/// Where an IPv6 probe goes out: from this local address, to the all-nodes group on the interface
/// with this index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MulticastTarget {
    pub local: Ipv6Addr,
    pub scope_id: u32,
}

/// An address a probe can be sent from and an answer come back to without a zone: not
/// unspecified, loopback, multicast or link-local (`fe80::/10`). A link-local address needs the
/// interface it belongs to to be reached, which a server's address on a link cannot carry, so a
/// client probes from an address that is not one and takes answers from addresses that are not.
pub(super) fn is_routable_v6(address: Ipv6Addr) -> bool {
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || is_link_local_v6(address))
}

/// `fe80::/10`.
pub(super) fn is_link_local_v6(address: Ipv6Addr) -> bool {
    (address.segments()[0] & 0xffc0) == 0xfe80
}

/// An IPv6-only UDP socket bound to `local` and a free port. IPv6 only so it is the same on every
/// system, and so an IPv4 socket never has to share it.
pub(super) fn bind_ipv6(local: Ipv6Addr) -> io::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_only_v6(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddr::new(IpAddr::V6(local), 0).into())?;
    UdpSocket::from_std(socket.into())
}

/// The all-nodes group a probe is sent to on each IPv6 network, `ff02::1`.
pub(super) const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// One interface that is up, is not loopback and has a routable IPv6 address, with that address:
/// the one to probe from. At most one per interface, so a host with several addresses (privacy
/// addresses among them) does not open a socket for each.
pub(super) fn multicast_targets() -> Vec<MulticastTarget> {
    let mut targets: Vec<MulticastTarget> = vec![];
    for interface in if_addrs::get_if_addrs().unwrap_or_default() {
        if interface.is_loopback() || !interface.is_oper_up() {
            continue;
        }
        let (Some(index), if_addrs::IfAddr::V6(v6)) = (interface.index, &interface.addr) else {
            continue;
        };
        if is_routable_v6(v6.ip) && !targets.iter().any(|t| t.scope_id == index) {
            targets.push(MulticastTarget {
                local: v6.ip,
                scope_id: index,
            });
        }
    }
    targets
}

/// The limited broadcast address and each IPv4 network's own broadcast address. On a machine with
/// several networks the limited one only leaves through one of them.
pub(super) fn broadcast_targets(port: u16) -> Vec<SocketAddr> {
    let mut targets = vec![Ipv4Addr::BROADCAST];
    for interface in if_addrs::get_if_addrs().unwrap_or_default() {
        if interface.is_loopback() || !interface.is_oper_up() {
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
    physical_v6: Vec<(Ipv6Addr, Ipv6Addr)>,
    until: Option<Instant>,
}

impl Networks {
    const REREAD: Duration = Duration::from_secs(10);

    pub(super) fn rank(&mut self, address: IpAddr) -> i32 {
        if self.until.is_none_or(|until| Instant::now() >= until) {
            let physical: Vec<if_addrs::Interface> = if_addrs::get_if_addrs()
                .unwrap_or_default()
                .into_iter()
                .filter(|i| !i.is_loopback() && !is_virtual(&i.name))
                .collect();
            self.physical = physical
                .iter()
                .filter_map(|i| match &i.addr {
                    if_addrs::IfAddr::V4(v4) => Some((v4.ip, v4.netmask)),
                    if_addrs::IfAddr::V6(_) => None,
                })
                .collect();
            self.physical_v6 = physical
                .iter()
                .filter_map(|i| match &i.addr {
                    if_addrs::IfAddr::V6(v6) => Some((v6.ip, v6.netmask)),
                    if_addrs::IfAddr::V4(_) => None,
                })
                .collect();
            self.until = Some(Instant::now() + Self::REREAD);
        }
        let on_physical = match address {
            IpAddr::V4(address) => self.physical.iter().any(|(ip, mask)| {
                (u32::from(address) & u32::from(*mask)) == (u32::from(*ip) & u32::from(*mask))
            }),
            IpAddr::V6(address) => self.physical_v6.iter().any(|(ip, mask)| {
                (u128::from(address) & u128::from(*mask)) == (u128::from(*ip) & u128::from(*mask))
            }),
        };
        if on_physical { 0 } else { 1 }
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
