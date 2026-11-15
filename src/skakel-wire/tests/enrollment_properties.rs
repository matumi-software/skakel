//! Properties of enrolling with a pairing code or a server key.

use proptest::prelude::*;
use skakel_wire::enrollment::{
    ConfirmKeys, End, KEY_PREFIX, KeyError, ServerKey, code_transcript, key_transcript, new_code, normalise_code,
};

fn fingerprint() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

proptest! {
    /// A key written as text reads back as the same key, whatever the case it is typed in.
    #[test]
    fn a_key_survives_its_text_form(fp in fingerprint()) {
        let key = ServerKey::generate(&fp).unwrap();
        let text = key.encode();
        prop_assert!(text.starts_with(KEY_PREFIX));
        prop_assert_eq!(text.len(), KEY_PREFIX.len() + 77);
        let back = ServerKey::parse(&text).unwrap();
        prop_assert!(key.same_secret(&back));
        prop_assert!(back.is_for(&fp));
        prop_assert_eq!(back.encode(), text.clone());
        let typed = ServerKey::parse(&format!("  {}  ", text.to_lowercase())).unwrap();
        prop_assert!(key.same_secret(&typed));
    }

    /// A key is for one certificate only: a fingerprint that differs in its first 16 bytes is refused.
    #[test]
    fn a_key_is_for_one_certificate(fp in fingerprint(), at in 0usize..16, flip in 1u8..=255) {
        let key = ServerKey::generate(&fp).unwrap();
        let mut other = fp;
        other[at] ^= flip;
        prop_assert!(!key.is_for(&other));
        // The last 16 bytes are not in the key, so a certificate differing only there is not told apart.
        let mut tail = fp;
        tail[20] ^= flip;
        prop_assert!(key.is_for(&tail));
    }

    /// A key MAC verifies for the same end, name, nonce and certificate and for nothing else.
    #[test]
    fn a_key_mac_binds_what_it_signs(
        fp in fingerprint(), other_fp in fingerprint(), name in ".{1,30}", other_name in ".{1,30}",
        nonce in "[A-Za-z0-9_-]{43}", other_nonce in "[A-Za-z0-9_-]{43}",
    ) {
        let key = ServerKey::generate(&fp).unwrap();
        let mac = key.mac(End::Client, &fp, &name, &nonce);
        prop_assert!(key.verify(End::Client, &fp, &name, &nonce, &mac));
        prop_assert!(!key.verify(End::Server, &fp, &name, &nonce, &mac));
        prop_assert_eq!(key.verify(End::Client, &other_fp, &name, &nonce, &mac), fp == other_fp);
        prop_assert_eq!(key.verify(End::Client, &fp, &other_name, &nonce, &mac), name == other_name);
        prop_assert_eq!(key.verify(End::Client, &fp, &name, &other_nonce, &mac), nonce == other_nonce);
        prop_assert!(!key.verify(End::Client, &fp, &name, &nonce, &mac[..31]));
        prop_assert!(!ServerKey::generate(&fp).unwrap().verify(End::Client, &fp, &name, &nonce, &mac));
    }

    /// The two ends' code MACs differ, verify only for their own transcript and need the same session key.
    #[test]
    fn a_code_mac_binds_the_transcript(
        key in prop::collection::vec(any::<u8>(), 16..64), other_key in prop::collection::vec(any::<u8>(), 16..64),
        fp in fingerprint(), other_fp in fingerprint(), name in ".{1,30}",
        client in prop::collection::vec(any::<u8>(), 32), server in prop::collection::vec(any::<u8>(), 32),
    ) {
        let keys = ConfirmKeys::derive(&key);
        let t = code_transcript(&fp, &name, &client, &server);
        let c = keys.mac(End::Client, &t);
        let s = keys.mac(End::Server, &t);
        prop_assert_ne!(c, s);
        prop_assert!(keys.verify(End::Client, &t, &c));
        prop_assert!(keys.verify(End::Server, &t, &s));
        prop_assert!(!keys.verify(End::Client, &t, &s));
        // A different certificate seen on one side is a different transcript: no match.
        let other_t = code_transcript(&other_fp, &name, &client, &server);
        prop_assert_eq!(keys.verify(End::Client, &other_t, &c), fp == other_fp);
        // A different session key (a wrong code) is no match.
        let others = ConfirmKeys::derive(&other_key);
        prop_assert_eq!(others.verify(End::Client, &t, &c), key == other_key);
    }

    /// Where one part of a transcript ends is part of it: moving a byte between parts changes it.
    #[test]
    fn a_transcript_keeps_its_parts_apart(fp in fingerprint(), a in "[a-z]{2,10}", b in "[a-z]{2,10}") {
        let one = key_transcript(&fp, &format!("{a}{b}"), "n");
        let two = key_transcript(&fp, &a, &format!("{b}n"));
        prop_assert_ne!(one, two);
    }

    /// A typed code is eight digits, with spaces and dashes allowed between them.
    #[test]
    fn a_typed_code_is_eight_digits(digits in "[0-9]{8}", junk in "[a-z]{1,3}") {
        prop_assert_eq!(normalise_code(&digits), Some(digits.clone()));
        prop_assert_eq!(normalise_code(&format!("{} {}", &digits[..4], &digits[4..])), Some(digits.clone()));
        prop_assert_eq!(normalise_code(&format!("{}-{}", &digits[..4], &digits[4..])), Some(digits.clone()));
        prop_assert_eq!(normalise_code(&format!("{digits}{junk}")), None);
        prop_assert_eq!(normalise_code(&digits[..7]), None);
    }
}

#[test]
fn a_new_code_is_eight_digits() {
    for _ in 0..200 {
        let code = new_code().unwrap();
        assert_eq!(code.len(), 8);
        assert!(code.bytes().all(|b| b.is_ascii_digit()));
    }
}

#[test]
fn a_bad_key_says_why() {
    assert_eq!(ServerKey::parse("hello").unwrap_err(), KeyError::Prefix);
    assert_eq!(ServerKey::parse("kp1_").unwrap_err(), KeyError::Malformed);
    assert_eq!(ServerKey::parse(&format!("{KEY_PREFIX}{}", "0".repeat(76))).unwrap_err(), KeyError::Malformed);
    assert_eq!(ServerKey::parse(&format!("{KEY_PREFIX}{}", "0".repeat(78))).unwrap_err(), KeyError::Malformed);
    // 77 characters carry 385 bits, so the last one has a spare bit that must be zero.
    assert_eq!(ServerKey::parse(&format!("{KEY_PREFIX}{}1", "0".repeat(76))).unwrap_err(), KeyError::Malformed);
    assert_eq!(ServerKey::parse(&format!("{KEY_PREFIX}{}U", "0".repeat(76))).unwrap_err(), KeyError::Malformed);
}

/// The key format and the transcript are pinned: a change here is a protocol change.
#[test]
fn the_key_and_transcript_are_pinned() {
    let fp = [0xAB; 32];
    let t = key_transcript(&fp, "bench-3", "NONCE");
    // lp("skakel-enroll-key-v1") + lp(fp) + lp("bench-3") + lp("NONCE")
    let mut expected = Vec::new();
    for part in [&b"skakel-enroll-key-v1"[..], &fp[..], b"bench-3", b"NONCE"] {
        expected.extend_from_slice(&(part.len() as u32).to_be_bytes());
        expected.extend_from_slice(part);
    }
    assert_eq!(t, expected);
    let key = ServerKey::parse(&format!("{KEY_PREFIX}{}", "0".repeat(77))).unwrap();
    assert_eq!(key.encode(), format!("{KEY_PREFIX}{}", "0".repeat(77)));
}
