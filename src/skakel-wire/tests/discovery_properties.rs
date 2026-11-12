//! Properties of the discovery packet: what a server builds, a client reads, and nothing a
//! stranger sends makes either panic or break a limit.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use proptest::prelude::*;
use skakel_wire::SkakelApp;
use skakel_wire::discovery::{
    DiscoveryAnswer, MAX_APP_VERSION_LENGTH, MAX_NAME_LENGTH, MAX_VERSIONS, PROBE_SIZE, clean,
    create_answer, create_probe, net::should_answer, try_parse_answer,
};

/// Text of any characters, control and format ones included, long enough to need cutting.
fn texts() -> impl Strategy<Value = String> {
    proptest::collection::vec(any::<char>(), 0..200).prop_map(|c| c.into_iter().collect())
}

fn answers() -> impl Strategy<Value = DiscoveryAnswer> {
    (
        texts(),
        1u16..,
        "[0-9A-F]{64}",
        "[a-z0-9-]{1,32}",
        texts(),
        proptest::collection::vec(1u32..1000, 1..=MAX_VERSIONS),
    )
        .prop_map(
            |(name, port, fingerprint, id, version, versions)| DiscoveryAnswer {
                name,
                port,
                fingerprint,
                app: SkakelApp { id, version },
                versions,
            },
        )
}

fn length(text: &str) -> usize {
    text.chars().count()
}

fn lan_address() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)), 50_000)
}

proptest! {
    /// An answer a server builds fits in a probe, and a client reads it back with the name and
    /// version cleaned and nothing else changed.
    #[test]
    fn an_answer_fits_a_probe_and_reads_back(answer in answers()) {
        let bytes = create_answer(&answer).expect("every field is within its limit");
        prop_assert!(bytes.len() <= PROBE_SIZE);
        let read = try_parse_answer(&bytes).expect("a client reads what a server builds");
        prop_assert_eq!(read.port, answer.port);
        prop_assert_eq!(&read.versions, &answer.versions);
        prop_assert_eq!(&read.app.id, &answer.app.id);
        prop_assert!(length(&read.name) <= MAX_NAME_LENGTH);
        prop_assert!(length(&read.app.version) <= MAX_APP_VERSION_LENGTH);
        // What a client reads is already clean, so cleaning it again changes nothing.
        prop_assert_eq!(clean(&read.name, MAX_NAME_LENGTH), read.name);
    }

    /// A built answer is one a server may send to a probe.
    #[test]
    fn a_built_answer_is_one_a_server_may_send(answer in answers()) {
        let bytes = create_answer(&answer).expect("every field is within its limit");
        prop_assert!(should_answer(&create_probe(), lan_address(), &bytes));
    }

    /// Any bytes at all are an answer or nothing, never a panic.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = try_parse_answer(&bytes);
        let _ = should_answer(&bytes, lan_address(), &bytes);
    }

    /// Bytes that start like an answer and go on as anything still obey the limits.
    #[test]
    fn a_parsed_answer_always_obeys_the_limits(tail in proptest::collection::vec(any::<u8>(), 0..600)) {
        let mut bytes = b"SKAKEL-SERVER/1\n".to_vec();
        bytes.extend_from_slice(&tail);
        if let Some(answer) = try_parse_answer(&bytes) {
            prop_assert!(length(&answer.name) <= MAX_NAME_LENGTH);
            prop_assert!(length(&answer.app.version) <= MAX_APP_VERSION_LENGTH);
            prop_assert!((1..=MAX_VERSIONS).contains(&answer.versions.len()));
            prop_assert!(answer.port != 0);
        }
    }

    /// Cleaning is idempotent, cuts to the length, and leaves nothing a person cannot be shown.
    #[test]
    fn clean_is_idempotent_and_bounded(text in texts(), max in 0usize..80) {
        let once = clean(&text, max);
        prop_assert!(length(&once) <= max);
        prop_assert_eq!(clean(&once, max), once.clone());
        prop_assert_eq!(once.trim(), once.as_str());
        prop_assert!(once.chars().all(|c| !c.is_control()));
    }

    /// A server never answers a datagram that is not a full-size probe, nor with more bytes than
    /// the datagram had.
    #[test]
    fn a_server_never_amplifies(
        datagram in proptest::collection::vec(any::<u8>(), 0..1024),
        answer in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        if should_answer(&datagram, lan_address(), &answer) {
            prop_assert!(datagram.len() >= PROBE_SIZE);
            prop_assert!(answer.len() <= datagram.len());
        }
    }
}
