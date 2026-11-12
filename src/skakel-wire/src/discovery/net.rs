//! The rule for what a server answers. Sockets, which interfaces to broadcast on, the list of
//! servers found and the limits on it belong to the server and the client.

use std::net::{IpAddr, SocketAddr};

use super::is_probe;

/// Whether a probe can be answered at all: it came from a port, and from one host. Port 0 and the
/// unspecified, broadcast and multicast addresses are not places an answer can go; on some systems
/// sending to them fails outright. An IPv4-mapped IPv6 address counts as its IPv4 address.
fn can_answer(from: SocketAddr) -> bool {
    if from.port() == 0 {
        return false;
    }
    match from.ip() {
        IpAddr::V4(address) => octet_is_unicast(address.octets()[0]),
        IpAddr::V6(address) => match address.to_ipv4_mapped() {
            Some(mapped) => octet_is_unicast(mapped.octets()[0]),
            None => !address.is_unspecified() && !address.is_multicast(),
        },
    }
}

/// 0.0.0.0/8 is "this network", 224.0.0.0/4 multicast, and everything from 240.0.0.0 up reserved
/// or broadcast.
fn octet_is_unicast(first: u8) -> bool {
    (1..224).contains(&first)
}

/// Whether a server answers this datagram with this answer: it is a probe, it came from somewhere
/// an answer can go, and the answer is no larger than the probe.
pub fn should_answer(datagram: &[u8], from: SocketAddr, answer: &[u8]) -> bool {
    is_probe(datagram) && can_answer(from) && answer.len() <= datagram.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SkakelApp;
    use crate::discovery::{DiscoveryAnswer, create_answer, create_probe};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn answer_bytes() -> Vec<u8> {
        create_answer(&DiscoveryAnswer {
            name: "pi-lab".into(),
            port: 5240,
            fingerprint: "EF".repeat(32),
            app: SkakelApp {
                id: "koppel".into(),
                version: "0.1.1".into(),
            },
            versions: vec![1],
        })
        .unwrap()
    }

    fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
    }

    #[test]
    fn can_answer_refuses_port_zero_and_addresses_that_are_not_one_host() {
        assert!(can_answer(v4(192, 168, 1, 20, 5000)));
        assert!(can_answer(v4(127, 0, 0, 1, 1)));
        assert!(!can_answer(v4(192, 168, 1, 20, 0)));
        assert!(!can_answer(v4(0, 0, 0, 0, 5000)));
        assert!(!can_answer(v4(0, 1, 2, 3, 5000)));
        assert!(!can_answer(v4(224, 0, 0, 1, 5000)));
        assert!(!can_answer(v4(239, 255, 255, 250, 5000)));
        assert!(!can_answer(v4(255, 255, 255, 255, 5000)));
        assert!(can_answer(v4(223, 255, 255, 255, 5000)));
    }

    #[test]
    fn can_answer_judges_ipv6_and_mapped_addresses() {
        let at = |address: Ipv6Addr| SocketAddr::new(IpAddr::V6(address), 5000);

        assert!(can_answer(at(Ipv6Addr::LOCALHOST)));
        assert!(can_answer(at("fe80::1".parse().unwrap())));
        assert!(!can_answer(at(Ipv6Addr::UNSPECIFIED)));
        assert!(!can_answer(at("ff02::1".parse().unwrap())));
        assert!(can_answer(at("::ffff:192.168.1.5".parse().unwrap())));
        assert!(!can_answer(at("::ffff:224.0.0.1".parse().unwrap())));
        assert!(!can_answer(at("::ffff:0.0.0.0".parse().unwrap())));
    }

    #[test]
    fn should_answer_wants_a_probe_a_place_to_answer_and_room_in_the_probe() {
        let from = v4(192, 168, 1, 20, 5000);
        let answer = answer_bytes();

        assert!(should_answer(&create_probe(), from, &answer));
        assert!(!should_answer(&create_probe()[..511], from, &answer));
        assert!(!should_answer(
            &create_probe(),
            v4(192, 168, 1, 20, 0),
            &answer
        ));
        assert!(!should_answer(&vec![0; 512], from, &answer));
        assert!(!should_answer(&create_probe(), from, &vec![0; 513]));
    }
}
