//! Small helpers the parts share: random ids and secrets, secret hashes, address keys and the
//! cleaning of a client's name.

use std::net::IpAddr;

use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const SHA256_PREFIX: &str = "sha256$";

/// The longest client name a pairing request may carry, in UTF-16 code units, the unit
/// the protocol counts in.
pub(crate) const MAX_CLIENT_NAME_LENGTH: usize = 80;

pub(crate) fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).expect("the operating system gave no random bytes");
    bytes
}

/// A client secret: 32 random bytes as base64url, without padding.
pub(crate) fn new_secret() -> String {
    URL_SAFE_NO_PAD.encode(random::<32>())
}

/// An id such as `client-3fa9c01b2e`.
pub(crate) fn new_id(prefix: &str) -> String {
    format!("{prefix}-{}", hex_lower(&random::<5>()))
}

/// The first id `make` gives that `taken` does not claim.
pub(crate) fn first_free(mut make: impl FnMut() -> String, taken: impl Fn(&str) -> bool) -> String {
    loop {
        let id = make();
        if !taken(&id) {
            return id;
        }
    }
}

/// A poll token: 32 random bytes as uppercase hex.
pub(crate) fn new_token() -> String {
    hex_upper(&random::<32>())
}

pub(crate) fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// What the server keeps of a client's secret. The secret is 256 random bits, so a plain SHA-256
/// is enough; there is nothing to guess and nothing to stretch.
pub(crate) fn hash_secret(secret: &str) -> String {
    format!(
        "{SHA256_PREFIX}{}",
        STANDARD.encode(Sha256::digest(secret.as_bytes()))
    )
}

pub(crate) fn verify_secret(secret: &str, stored_hash: &str) -> bool {
    if secret.is_empty() {
        return false;
    }
    let Some(encoded) = stored_hash.strip_prefix(SHA256_PREFIX) else {
        return false;
    };
    let Ok(expected) = STANDARD.decode(encoded) else {
        return false;
    };
    Sha256::digest(secret.as_bytes())
        .as_slice()
        .ct_eq(&expected)
        .into()
}

/// The token in an `Authorization: Bearer <token>` header, when there is one.
pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
}

/// Constant-time comparison of a presented token with the one that was handed out.
pub(crate) fn same_token(expected: &str, presented: Option<&str>) -> bool {
    match presented {
        Some(presented) if !presented.is_empty() => {
            expected.as_bytes().ct_eq(presented.as_bytes()).into()
        }
        _ => false,
    }
}

/// The address as text, with an IPv4-mapped IPv6 address as its IPv4 address. What the app sees as
/// where a request came from.
pub(crate) fn address_text(address: IpAddr) -> String {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4).to_string(),
        IpAddr::V4(_) => address.to_string(),
    }
}

/// The key a per-address limit counts under. An IPv4 address, or an IPv4-mapped IPv6 address, counts
/// as itself. An IPv6 address counts as its `/64`, because one host on a network owns a whole `/64`
/// and can take any address in it, so counting whole addresses would let it spend a limit as often
/// as it likes.
pub(crate) fn address_key(address: IpAddr) -> String {
    match address {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
        IpAddr::V4(_) => address.to_string(),
    }
}

pub(crate) fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_free_skips_the_ids_that_are_taken() {
        let mut ids = ["a", "b", "c"].into_iter().map(String::from);

        let id = first_free(|| ids.next().unwrap(), |id| id != "c");

        assert_eq!(id, "c");
    }

    #[test]
    fn secrets_are_43_url_safe_characters_and_never_repeat() {
        let secret = new_secret();

        assert_eq!(secret.len(), 43);
        assert!(
            secret
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        assert_ne!(secret, new_secret());
    }

    #[test]
    fn ids_and_tokens_have_their_pinned_shapes() {
        let id = new_id("client");

        assert!(id.starts_with("client-"));
        assert_eq!(id.len(), "client-".len() + 10);
        assert_eq!(new_token().len(), 64);
        assert!(new_token().bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn a_secret_verifies_against_its_own_hash_and_no_other() {
        let hash = hash_secret("s3cret");

        assert!(hash.starts_with("sha256$"));
        assert!(verify_secret("s3cret", &hash));
        assert!(!verify_secret("other", &hash));
        assert!(!verify_secret("", &hash));
        assert!(!verify_secret("s3cret", "plain"));
        assert!(!verify_secret("s3cret", "sha256$not base64!"));
    }

    #[test]
    fn the_hash_is_the_pinned_one() {
        // SHA-256 of "abc", standard base64.
        assert_eq!(
            hash_secret("abc"),
            "sha256$ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
        );
    }

    #[test]
    fn same_token_wants_a_value_that_is_equal() {
        assert!(same_token("ABC", Some("ABC")));
        assert!(!same_token("ABC", Some("ABD")));
        assert!(!same_token("ABC", Some("")));
        assert!(!same_token("ABC", None));
    }

    #[test]
    fn address_key_counts_a_mapped_address_as_its_ipv4_address() {
        let mapped: IpAddr = "::ffff:10.1.2.3".parse().unwrap();

        assert_eq!(address_key(mapped), "10.1.2.3");
        assert_eq!(address_key("10.1.2.3".parse().unwrap()), "10.1.2.3");
    }

    #[test]
    fn address_key_counts_an_ipv6_address_as_its_64() {
        let one: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let other: IpAddr = "2001:db8:1:2:ffff:ffff:ffff:ffff".parse().unwrap();
        let next: IpAddr = "2001:db8:1:3::1".parse().unwrap();

        assert_eq!(address_key(one), "2001:db8:1:2::/64");
        assert_eq!(address_key(one), address_key(other));
        assert_ne!(address_key(one), address_key(next));
    }

    #[test]
    fn address_text_is_the_whole_address_with_a_mapped_one_as_ipv4() {
        assert_eq!(address_text("::ffff:10.1.2.3".parse().unwrap()), "10.1.2.3");
        assert_eq!(address_text("2001:db8::1".parse().unwrap()), "2001:db8::1");
    }
}

#[cfg(test)]
mod properties {
    use std::net::{IpAddr, Ipv6Addr};

    use axum::http::{HeaderMap, HeaderValue, header::AUTHORIZATION};
    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// Every address of one IPv6 `/64` counts under one key, and an address of another `/64`
        /// under another, so rotating the low 64 bits spends nothing new.
        #[test]
        fn an_ipv6_64_is_one_key(high in any::<u64>(), a in any::<u64>(), b in any::<u64>(), other in any::<u16>()) {
            // An address that is not IPv4-mapped (::ffff:0:0/96), so the /64 rule applies.
            let make = |high: u64, low: u64| IpAddr::V6(Ipv6Addr::from(((u128::from(high) | 1 << 63) << 64) | u128::from(low)));
            prop_assert_eq!(address_key(make(high, a)), address_key(make(high, b)));
            let moved = make(high ^ (u64::from(other) | 1), a);
            prop_assert_ne!(address_key(make(high, a)), address_key(moved));
        }

        /// An IPv4-mapped address counts as the IPv4 address it holds.
        #[test]
        fn a_mapped_address_is_its_ipv4_address(octets in any::<[u8; 4]>()) {
            let v4 = std::net::Ipv4Addr::from(octets);
            prop_assert_eq!(address_key(IpAddr::V6(v4.to_ipv6_mapped())), address_key(IpAddr::V4(v4)));
        }

        /// A bearer token is read from any header value or refused, never a panic.
        #[test]
        fn a_bearer_header_is_read_or_refused(value in proptest::collection::vec(32u8..127, 0..120)) {
            let mut headers = HeaderMap::new();
            headers.insert(AUTHORIZATION, HeaderValue::from_bytes(&value).unwrap());
            let _ = bearer_token(&headers);
        }

        /// The length in UTF-16 units is the standard library's own count.
        #[test]
        fn utf16_length_is_the_encoders(text in ".{0,100}") {
            prop_assert_eq!(utf16_len(&text), text.encode_utf16().count());
        }
    }
}
