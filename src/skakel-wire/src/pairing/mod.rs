//! The Skakel pairing code and the JSON bodies of the pairing calls. See `docs/protocol.md`
//! ("Pairing") and `docs/parts.md` at the repository root.
//!
//! Pairing is numeric comparison with a commitment, as in Bluetooth pairing:
//!
//! 1. The client sends [`commit`] of a random nonce, not the nonce.
//! 2. The server answers with its own random nonce.
//! 3. The client reveals its nonce; the server checks it with [`matches()`].
//!
//! Both ends then derive the code with [`compute`] from the certificate the client pinned, the name
//! the client sent and both nonces. A man in the middle has its own certificate and must fix each
//! nonce before it sees the other side's, so it cannot steer the two codes to match: for each
//! request it gets one guess in a hundred million. Because the name is part of the code, a man in
//! the middle who shows the person another name than the client's gets a code that does not match.
//! That holds per request, not overall, so the server also limits how many requests it takes. The
//! code is never sent.
//!
//! Every hash input is length-prefixed (a 4-byte big-endian length before each part), so no two
//! different inputs give the same bytes to hash.

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
pub const DIGITS: usize = 8;

/// The code is a number below this, shown with [`DIGITS`] digits.
const CODE_MODULUS: u64 = 100_000_000;

/// The word that starts the commitment's hash input, and with it the commitment's version.
const COMMIT_TAG: &str = "skakel-commit-v2";

/// The word that starts the code's hash input, and with it the derivation's version.
const CODE_TAG: &str = "skakel-pair-v2";

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

/// The bytes a hash is taken over: each part after a 4-byte big-endian length, so where one part
/// ends and the next begins is never open to doubt.
fn framed(parts: &[&[u8]]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(parts.iter().map(|p| p.len() + 4).sum());
    for part in parts {
        // A part longer than 4 GiB cannot arrive over the wire (bodies are capped at 4 KiB).
        let length = u32::try_from(part.len()).unwrap_or(u32::MAX);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(part);
    }
    bytes
}

/// The commitment a client sends before revealing its nonce: the uppercase hex SHA-256 of
/// `"skakel-commit-v2"` and the nonce's UTF-8 bytes, each after its length.
pub fn commit(nonce: &str) -> String {
    let hash = Sha256::digest(framed(&[COMMIT_TAG.as_bytes(), nonce.as_bytes()]));
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

/// The 32 bytes of a fingerprint written as 64 hex digits, with or without colons between them, or
/// `None` for anything else.
fn fingerprint_bytes(fingerprint: &str) -> Option<[u8; 32]> {
    let mut bytes = [0u8; 32];
    let mut digits = fingerprint.chars().filter(|c| *c != ':');
    for byte in &mut bytes {
        let high = digits.next()?.to_digit(16)?;
        let low = digits.next()?.to_digit(16)?;
        *byte = u8::try_from(high * 16 + low).ok()?;
    }
    if digits.next().is_some()
        || fingerprint
            .chars()
            .any(|c| c != ':' && !c.is_ascii_hexdigit())
    {
        return None;
    }
    Some(bytes)
}

/// The code, such as `48291377`, or `None` when `fingerprint` is not a fingerprint: exactly 64 hex
/// digits, with or without colons between them, and nothing else. Fingerprints compare by their hex
/// digits alone, so it makes no difference how a valid one is written (case, colons).
///
/// `client_name` is the name exactly as the client sent it in its opening call, before the server
/// cleaned it. The code is the first 8 bytes, as a big-endian `u64`, of the SHA-256 of
/// `"skakel-pair-v2"`, the fingerprint's 32 bytes, the name and the two nonces, each after its
/// length, modulo 10^8.
pub fn compute(
    fingerprint: &str,
    client_name: &str,
    client_nonce: &str,
    server_nonce: &str,
) -> Option<String> {
    let fingerprint = fingerprint_bytes(fingerprint)?;
    let hash = Sha256::digest(framed(&[
        CODE_TAG.as_bytes(),
        &fingerprint,
        client_name.as_bytes(),
        client_nonce.as_bytes(),
        server_nonce.as_bytes(),
    ]));
    let value = u64::from_be_bytes([
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
    ]) % CODE_MODULUS;
    Some(format!("{value:0DIGITS$}"))
}

/// Compares a typed code with the expected one, ignoring anything but ASCII digits, in constant
/// time. Typed text without exactly eight digits is never the code.
pub fn is_code(expected: &str, typed: &str) -> bool {
    let digits: String = typed.chars().filter(char::is_ascii_digit).collect();
    digits.len() == DIGITS && bool::from(expected.as_bytes().ct_eq(digits.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FINGERPRINT: &str = "EF:8E:16:AF:C3:88:BF:8C:94:CB:98:9A:3F:6A:93:F9:3D:0B:30:60:33:87:79:CF:C0:A4:E6:A4:30:89:14:29";

    // The pinned values below were worked out with an independent implementation (a few lines of
    // Python: `struct.pack(">I", len(part)) + part` for each part, `hashlib.sha256`, the first 8
    // bytes as a big-endian integer, modulo 10**8), not with this crate.

    fn is_upper_hex(text: &str, length: usize) -> bool {
        text.len() == length && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'A'..=b'F'))
    }

    #[test]
    fn compute_gives_the_same_eight_digits_however_the_fingerprint_is_written() {
        let code = compute(FINGERPRINT, "lab pc", "client-nonce", "server-nonce").unwrap();

        assert_eq!(code.len(), 8);
        assert!(code.bytes().all(|b| b.is_ascii_digit()));
        let plain = FINGERPRINT.replace(':', "").to_ascii_lowercase();
        assert_eq!(
            compute(&plain, "lab pc", "client-nonce", "server-nonce").unwrap(),
            code
        );
    }

    #[test]
    fn compute_refuses_text_that_is_not_a_fingerprint() {
        let colonless = FINGERPRINT.replace(':', "");
        assert_eq!(compute(&format!("{FINGERPRINT}!"), "n", "c", "s"), None);
        assert_eq!(compute(&format!("zz:{FINGERPRINT}"), "n", "c", "s"), None);
        assert_eq!(compute(&format!(" {colonless}"), "n", "c", "s"), None);
        assert_eq!(compute(&colonless[..62], "n", "c", "s"), None);
        assert_eq!(compute(&format!("{colonless}AB"), "n", "c", "s"), None);
        assert_eq!(compute("", "n", "c", "s"), None);
        assert_eq!(compute(":::", "n", "c", "s"), None);
    }

    #[test]
    fn compute_gives_the_pinned_code() {
        assert_eq!(
            compute(FINGERPRINT, "lab pc", "c", "s").unwrap(),
            "65578793"
        );
        assert_eq!(
            compute(FINGERPRINT, "lab pc", "client-nonce", "server-nonce").unwrap(),
            "82202962"
        );
    }

    #[test]
    fn compute_gives_another_code_for_another_client_name() {
        // A man in the middle that shows the person another name than the client sent gets a
        // code that does not match the one on the client's screen.
        let shown = compute(FINGERPRINT, "lab pc", "client-nonce", "server-nonce").unwrap();
        let swapped = compute(FINGERPRINT, "other pc", "client-nonce", "server-nonce").unwrap();

        assert_ne!(shown, swapped);
        assert_eq!(swapped, "52514043");
    }

    #[test]
    fn compute_follows_the_derivation_in_the_protocol() {
        // The first 8 bytes of the SHA-256 of the length-prefixed parts, big-endian, mod 10^8.
        let fingerprint: Vec<u8> = (0..32)
            .map(|i| {
                u8::from_str_radix(&FINGERPRINT.replace(':', "")[i * 2..i * 2 + 2], 16).unwrap()
            })
            .collect();
        let mut input = Vec::new();
        for part in [
            b"skakel-pair-v2".as_slice(),
            &fingerprint,
            b"lab pc",
            b"c",
            b"s",
        ] {
            input.extend_from_slice(&(part.len() as u32).to_be_bytes());
            input.extend_from_slice(part);
        }
        let hash = Sha256::digest(&input);
        let expected = u64::from_be_bytes(hash[..8].try_into().unwrap()) % 100_000_000;

        assert_eq!(
            compute(FINGERPRINT, "lab pc", "c", "s").unwrap(),
            format!("{expected:08}")
        );
    }

    #[test]
    fn compute_pads_a_small_code_to_eight_digits() {
        // A code that starts with zeros, found by search, which must keep its zeros.
        assert_eq!(
            compute(FINGERPRINT, "lab pc", "pad-1708", "s").unwrap(),
            "00045024"
        );
    }

    #[test]
    fn compute_gives_another_code_for_another_certificate_or_nonce() {
        let code = compute(FINGERPRINT, "n", "a", "b").unwrap();

        assert_ne!(
            compute(&FINGERPRINT.replace("EF", "EE"), "n", "a", "b").unwrap(),
            code
        );
        assert_ne!(compute(FINGERPRINT, "n", "a2", "b").unwrap(), code);
        assert_ne!(compute(FINGERPRINT, "n", "a", "b2").unwrap(), code);
    }

    #[test]
    fn compute_does_not_let_the_end_of_one_part_move_into_the_next() {
        // With plain concatenation these would hash the same bytes.
        assert_ne!(
            compute(FINGERPRINT, "ab", "c", "s").unwrap(),
            compute(FINGERPRINT, "a", "bc", "s").unwrap()
        );
        assert_ne!(
            compute(FINGERPRINT, "n", "ab", "c").unwrap(),
            compute(FINGERPRINT, "n", "a", "bc").unwrap()
        );
    }

    #[test]
    fn commit_is_the_uppercase_hex_sha256_of_the_tagged_nonce() {
        assert_eq!(
            commit("client-nonce"),
            "D20434E33502B13B9DC70E78547F72F4CF51E4428688B48B511867FCE7360940"
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
    fn is_code_ignores_spaces_but_wants_all_eight_digits() {
        assert!(is_code("48291377", "4829 1377"));
        assert!(!is_code("48291377", "48291378"));
        assert!(!is_code("48291377", "482913"));
        assert!(!is_code("48291377", "482913770"));
        assert!(!is_code("48291377", ""));
    }
}
