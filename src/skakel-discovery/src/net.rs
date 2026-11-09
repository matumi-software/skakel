//! The UDP side that a server and a client both need, on `std::net::UdpSocket`.
//!
//! Which interfaces to broadcast on, the list of servers found and the limits on it belong to the
//! client; this is the rule for what a server answers, one receive loop step, and one probe.

use std::io::{self, ErrorKind};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::{DiscoveryAnswer, create_probe, is_probe, try_parse_answer};

/// Whether a probe can be answered at all: it came from a port, and from one host. Port 0 and the
/// unspecified, broadcast and multicast addresses are not places an answer can go; on some systems
/// sending to them fails outright. An IPv4-mapped IPv6 address counts as its IPv4 address.
pub fn can_answer(from: SocketAddr) -> bool {
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

/// Receives one datagram on `socket` and, when [`should_answer`] says so, sends `answer` back to
/// where it came from. True when it answered.
///
/// Errors Windows reports on the next receive about an earlier datagram (an answer that could not
/// be delivered, a datagram larger than the buffer) are about that datagram alone and give
/// `Ok(false)`. A timeout the socket was given is an error, as for any receive, so a server that
/// wants to stop sets one and checks its flag.
pub fn serve_one(socket: &UdpSocket, answer: &[u8]) -> io::Result<bool> {
    let mut buffer = [0u8; 2048];
    let (received, from) = match socket.recv_from(&mut buffer) {
        Ok(received) => received,
        Err(error) if is_about_one_datagram(&error) => return Ok(false),
        Err(error) => return Err(error),
    };
    if !should_answer(&buffer[..received], from, answer) {
        return Ok(false);
    }
    // A failed send is about this one answer. The next probe still gets one.
    Ok(socket.send_to(answer, from).is_ok())
}

fn is_about_one_datagram(error: &io::Error) -> bool {
    // WSAEMSGSIZE (10040) is a datagram larger than the buffer; the standard library has no kind for it.
    error.kind() == ErrorKind::ConnectionReset
        || (cfg!(windows) && error.raw_os_error() == Some(10040))
}

/// A server that answered a probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The address and port the answer came from. A client reaches the server at this address, on
    /// the answer's `port`.
    pub from: SocketAddr,
    /// What the server said.
    pub answer: DiscoveryAnswer,
}

/// Sends one probe to `to` from `socket` and collects the answers that arrive within `wait`.
/// Datagrams that are not a valid answer are skipped.
pub fn probe(socket: &UdpSocket, to: SocketAddr, wait: Duration) -> io::Result<Vec<Found>> {
    socket.send_to(&create_probe(), to)?;
    let deadline = Instant::now() + wait;
    let mut found = Vec::new();
    let mut buffer = [0u8; 2048];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok(found);
        }
        socket.set_read_timeout(Some(left))?;
        match socket.recv_from(&mut buffer) {
            Ok((received, from)) => {
                if let Some(answer) = try_parse_answer(&buffer[..received]) {
                    found.push(Found { from, answer });
                }
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Ok(found);
            }
            Err(error) if is_about_one_datagram(&error) => {}
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DiscoveryAnswer, create_answer};
    use skakel_protocol::SkakelApp;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::thread;

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

    #[test]
    fn probe_finds_a_server_that_answers_on_loopback() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let target = server.local_addr().unwrap();
        let answer = answer_bytes();
        let served = {
            let answer = answer.clone();
            thread::spawn(move || serve_one(&server, &answer).unwrap())
        };
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();

        let found = probe(&client, target, Duration::from_millis(500)).unwrap();

        assert!(served.join().unwrap());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].from, target);
        assert_eq!(found[0].answer.name, "pi-lab");
        assert_eq!(found[0].answer.port, 5240);
    }

    #[test]
    fn probe_finds_nothing_when_nobody_answers() {
        let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();

        let found = probe(
            &client,
            silent.local_addr().unwrap(),
            Duration::from_millis(100),
        )
        .unwrap();

        assert!(found.is_empty());
    }

    #[test]
    fn serve_one_leaves_a_short_datagram_unanswered() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .send_to(&create_probe()[..100], server.local_addr().unwrap())
            .unwrap();

        assert!(!serve_one(&server, &answer_bytes()).unwrap());
    }
}
