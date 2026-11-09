//! Small helpers the parts share: random ids and secrets, secret hashes, address keys and the
//! cleaning of a client's name.

use std::net::IpAddr;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use unicode_general_category::{GeneralCategory, get_general_category};

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

/// A poll token: 32 random bytes as uppercase hex.
pub(crate) fn new_token() -> String {
    hex_upper(&random::<32>())
}

pub(crate) fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn hex_lower(bytes: &[u8]) -> String {
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

/// Constant-time comparison of a presented token with the one that was handed out.
pub(crate) fn same_token(expected: &str, presented: Option<&str>) -> bool {
    match presented {
        Some(presented) if !presented.is_empty() => {
            expected.as_bytes().ct_eq(presented.as_bytes()).into()
        }
        _ => false,
    }
}

/// The key a per-address limit counts under: the whole address, with an IPv4-mapped IPv6 address
/// as its IPv4 address.
pub(crate) fn address_key(address: IpAddr) -> String {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4).to_string(),
        IpAddr::V4(_) => address.to_string(),
    }
}

/// A client's name as the server keeps it: control and format characters (categories Cc and Cf)
/// taken out, then trimmed.
pub fn clean_client_name(name: &str) -> String {
    let kept: String = name
        .chars()
        .filter(|c| {
            !matches!(
                get_general_category(*c),
                GeneralCategory::Control | GeneralCategory::Format
            )
        })
        .collect();
    kept.trim().to_owned()
}

pub(crate) fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let v6: IpAddr = "2001:db8::1".parse().unwrap();

        assert_eq!(address_key(mapped), "10.1.2.3");
        assert_eq!(address_key("10.1.2.3".parse().unwrap()), "10.1.2.3");
        assert_eq!(address_key(v6), "2001:db8::1");
    }

    #[test]
    fn client_names_lose_control_and_format_characters_and_the_spaces_around() {
        assert_eq!(clean_client_name("  lab\u{0}\u{202E} pc \n"), "lab pc");
        assert_eq!(clean_client_name("\u{200B}\u{0}"), "");
        assert_eq!(clean_client_name("Zo\u{eb}"), "Zo\u{eb}");
    }
}
