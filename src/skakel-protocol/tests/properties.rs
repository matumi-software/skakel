//! Properties of fingerprints: how two texts compare, and what a client pins.

use proptest::prelude::*;
use skakel_protocol::fingerprints::{self, HEX_DIGITS};

proptest! {
    /// Normalising twice is normalising once, and what it gives is 32 colon-separated pairs.
    #[test]
    fn normalizing_is_idempotent(text in "[0-9a-fA-F]{64}") {
        let once = fingerprints::normalize(&text).expect("64 hex digits");
        prop_assert_eq!(once.len(), 95);
        prop_assert_eq!(fingerprints::normalize(&once), Some(once.clone()));
        prop_assert!(fingerprints::are_equal(&text, &once));
    }

    /// Any text at all is a fingerprint or nothing, never a panic, and a fingerprint is always 64
    /// digits.
    #[test]
    fn normalize_accepts_only_sixty_four_digits(text in ".{0,200}") {
        if let Some(normal) = fingerprints::normalize(&text) {
            prop_assert_eq!(normal.chars().filter(|c| *c != ':').count(), HEX_DIGITS);
        }
    }

    /// Equal is symmetric, and text without a hex digit is equal to nothing, itself included.
    #[test]
    fn equality_is_symmetric_and_needs_a_digit(a in ".{0,100}", b in ".{0,100}") {
        prop_assert_eq!(fingerprints::are_equal(&a, &b), fingerprints::are_equal(&b, &a));
        if !a.chars().any(|c| c.is_ascii_hexdigit()) {
            prop_assert!(!fingerprints::are_equal(&a, &a));
            prop_assert!(!fingerprints::are_equal(&a, &b));
        }
    }

    /// A certificate matches its own fingerprint, written any way, and no other certificate's.
    #[test]
    fn a_certificate_matches_only_its_own_fingerprint(
        a in proptest::collection::vec(any::<u8>(), 0..300),
        b in proptest::collection::vec(any::<u8>(), 0..300),
    ) {
        let fingerprint = fingerprints::of_der(&a);
        prop_assert!(fingerprints::matches_any_der(&a, [fingerprint.as_str()]));
        prop_assert!(fingerprints::matches_any_der(&a, [fingerprint.to_lowercase().as_str()]));
        prop_assert_eq!(fingerprints::matches_any_der(&b, [fingerprint.as_str()]), a == b);
    }
}
