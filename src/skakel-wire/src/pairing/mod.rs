//! The Skakel pairing code and the JSON bodies of the pairing calls. See `docs/protocol.md`
//! ("Pairing") and `docs/parts.md` at the repository root.
//!
//! Pairing is numeric comparison with a commitment, as in Bluetooth pairing:
//!
//! 1. The client sends [`commit`] of a random nonce, not the nonce.
//! 2. The server answers with its own random nonce.
//! 3. The client reveals its nonce; the server checks it with [`matches()`].
//!
//! Both ends then derive the code with [`compute`] from the certificate the client pinned and both
//! nonces. A man in the middle has its own certificate and must fix each nonce before it sees the
//! other side's, so it cannot steer the two codes to match: for each request it gets one guess in a
//! million. That holds per request, not overall, so the server also limits how many requests it
//! takes. The code is never sent.

mod bodies;
mod name;

pub use bodies::{
    PAIR_APPROVED, PAIR_DENIED, PAIR_EXPIRED, PAIR_WAITING, PairOpenRequest, PairOpened, PairPoll,
    PairRevealRequest, PairState,
};
pub use name::clean_client_name;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// How many digits the code has.
pub const DIGITS: usize = 6;

/// The operating system had no random numbers to give, so there is no safe nonce to make.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RandomError;

impl RandomError {
    /// The error for a source of random numbers that gave none.
    pub const fn new() -> Self {
        RandomError
    }
}

impl Default for RandomError {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for RandomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("The operating system gave no random bytes.")
    }
}

impl std::error::Error for RandomError {}

/// `N` random bytes from the operating system, or [`RandomError`] when it has none to give.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], RandomError> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|_| RandomError)?;
    Ok(bytes)
}

/// A fresh random nonce: 32 bytes as base64url, without padding, or [`RandomError`] when the
/// operating system has no random numbers to give.
pub fn new_nonce() -> Result<String, RandomError> {
    Ok(URL_SAFE_NO_PAD.encode(random_bytes::<32>()?))
}

/// The commitment a client sends before revealing its nonce: the uppercase hex SHA-256 of its
/// UTF-8 bytes.
pub fn commit(nonce: &str) -> String {
    let hash = Sha256::digest(nonce.as_bytes());
    hash.iter().map(|byte| format!("{byte:02X}")).collect()
}

/// True when `nonce` is the one `commitment` was made from, in constant time. Case is ignored.
pub fn matches(commitment: &str, nonce: &str) -> bool {
    commitment
        .to_ascii_uppercase()
        .as_bytes()
        .ct_eq(commit(nonce).as_bytes())
        .into()
}

/// The code, such as `482913`, or `None` when `fingerprint` is not a fingerprint: exactly 64 hex
/// digits, with or without colons between them, and nothing else. Fingerprints compare by their hex
/// digits alone, so it makes no difference how a valid one is written (case, colons).
pub fn compute(fingerprint: &str, client_nonce: &str, server_nonce: &str) -> Option<String> {
    if fingerprint
        .chars()
        .any(|c| c != ':' && !c.is_ascii_hexdigit())
    {
        return None;
    }
    let hex: String = fingerprint
        .chars()
        .filter(|c| *c != ':')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if hex.len() != 64 {
        return None;
    }
    let hash = Sha256::digest(format!(
        "skakel-pair-v1|{hex}|{client_nonce}|{server_nonce}"
    ));
    let value = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]) % 1_000_000;
    Some(format!("{value:06}"))
}

/// Compares a typed code with the expected one, ignoring anything but ASCII digits, in constant
/// time. Typed text without exactly six digits is never the code.
pub fn is_code(expected: &str, typed: &str) -> bool {
    let digits: String = typed.chars().filter(char::is_ascii_digit).collect();
    digits.len() == DIGITS && bool::from(expected.as_bytes().ct_eq(digits.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FINGERPRINT: &str = "EF:8E:16:AF:C3:88:BF:8C:94:CB:98:9A:3F:6A:93:F9:3D:0B:30:60:33:87:79:CF:C0:A4:E6:A4:30:89:14:29";

    fn is_upper_hex(text: &str, length: usize) -> bool {
        text.len() == length && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'A'..=b'F'))
    }

    #[test]
    fn compute_gives_the_same_six_digits_however_the_fingerprint_is_written() {
        let code = compute(FINGERPRINT, "client-nonce", "server-nonce").unwrap();

        assert_eq!(code.len(), 6);
        assert!(code.bytes().all(|b| b.is_ascii_digit()));
        let plain = FINGERPRINT.replace(':', "").to_ascii_lowercase();
        assert_eq!(
            compute(&plain, "client-nonce", "server-nonce").unwrap(),
            code
        );
    }

    #[test]
    fn compute_refuses_text_that_is_not_a_fingerprint() {
        // Before, any non-hex character was dropped and the rest hashed, so these gave a code.
        let colonless = FINGERPRINT.replace(':', "");
        assert_eq!(compute(&format!("{FINGERPRINT}!"), "c", "s"), None);
        assert_eq!(compute(&format!("zz:{FINGERPRINT}"), "c", "s"), None);
        assert_eq!(compute(&format!(" {colonless}"), "c", "s"), None);
        assert_eq!(compute(&colonless[..62], "c", "s"), None);
        assert_eq!(compute(&format!("{colonless}AB"), "c", "s"), None);
        assert_eq!(compute("", "c", "s"), None);
        assert_eq!(compute(":::", "c", "s"), None);
    }

    #[test]
    fn compute_gives_the_pinned_code() {
        assert_eq!(compute(FINGERPRINT, "c", "s").unwrap(), "749912");
        assert_eq!(
            compute(FINGERPRINT, "client-nonce", "server-nonce").unwrap(),
            "904104"
        );
    }

    #[test]
    fn compute_follows_the_derivation_in_the_protocol() {
        // The first four bytes of the SHA-256 of "skakel-pair-v1|<hex>|c|s", big-endian, mod 10^6.
        let hex = FINGERPRINT.replace(':', "");
        let hash = Sha256::digest(format!("skakel-pair-v1|{hex}|c|s"));
        let expected = u32::from_be_bytes(hash[..4].try_into().unwrap()) % 1_000_000;

        assert_eq!(
            compute(FINGERPRINT, "c", "s").unwrap(),
            format!("{expected:06}")
        );
    }

    #[test]
    fn compute_pads_a_small_code_to_six_digits() {
        // A code that starts with zeros, found by search, which must keep its zeros.
        assert_eq!(compute(FINGERPRINT, "pad-41", "s").unwrap(), "008456");
    }

    #[test]
    fn compute_gives_another_code_for_another_certificate_or_nonce() {
        let code = compute(FINGERPRINT, "a", "b").unwrap();

        assert_ne!(
            compute(&FINGERPRINT.replace("EF", "EE"), "a", "b").unwrap(),
            code
        );
        assert_ne!(compute(FINGERPRINT, "a2", "b").unwrap(), code);
        assert_ne!(compute(FINGERPRINT, "a", "b2").unwrap(), code);
    }

    #[test]
    fn commit_is_the_uppercase_hex_sha256() {
        assert_eq!(
            commit("client-nonce"),
            "A35525BDCB47F876099F1C74B3E19AB3EA4C8A7BF6FD2EAB6A3C35BE602551C6"
        );
        assert!(is_upper_hex(&commit("client-nonce"), 64));
    }

    #[test]
    fn matches_takes_only_the_nonce_the_commitment_was_made_from() {
        let nonce = new_nonce().unwrap();
        let commitment = commit(&nonce);

        assert!(matches(&commitment, &nonce));
        assert!(matches(&commitment.to_ascii_lowercase(), &nonce));
        assert!(!matches(&commitment, &new_nonce().unwrap()));
        assert!(!matches("", &nonce));
    }

    #[test]
    fn new_nonce_reports_a_failure_of_the_random_source_as_an_error_not_a_panic() {
        // The type is the point: a caller has to handle it. The error says what happened.
        let nonce: Result<String, RandomError> = new_nonce();
        assert!(nonce.is_ok());
        assert_eq!(
            RandomError.to_string(),
            "The operating system gave no random bytes."
        );
    }

    #[test]
    fn new_nonce_is_32_bytes_of_base64url() {
        let nonce = new_nonce().unwrap();

        assert_eq!(nonce.len(), 43);
        assert!(
            nonce
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        );
        assert_ne!(new_nonce().unwrap(), nonce);
    }

    #[test]
    fn is_code_ignores_spaces_but_wants_all_six_digits() {
        assert!(is_code("482913", "482 913"));
        assert!(!is_code("482913", "482914"));
        assert!(!is_code("482913", "48291"));
        assert!(!is_code("482913", "4829130"));
        assert!(!is_code("482913", ""));
    }
}
