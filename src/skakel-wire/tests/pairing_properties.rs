//! Properties of the pairing code and the names a client gives.

use proptest::prelude::*;
use skakel_wire::pairing::{DIGITS, clean_client_name, commit, compute, is_code, matches};

proptest! {
    /// A commitment matches its own nonce in any letter case and no other nonce.
    #[test]
    fn a_commitment_matches_only_its_nonce(a in ".{0,80}", b in ".{0,80}") {
        let commitment = commit(&a);
        prop_assert_eq!(commitment.len(), 64);
        prop_assert!(matches(&commitment, &a));
        prop_assert!(matches(&commitment.to_lowercase(), &a));
        prop_assert_eq!(matches(&commitment, &b), a == b);
    }

    /// The code is always eight digits, and the same inputs give the same code however the
    /// fingerprint is written.
    #[test]
    fn the_code_is_eight_digits_and_stable(
        fp in "[0-9A-F]{64}", name in ".{0,40}", c in ".{0,60}", s in ".{0,60}",
    ) {
        let code = compute(&fp, &name, &c, &s).unwrap();
        prop_assert_eq!(code.len(), DIGITS);
        prop_assert!(code.bytes().all(|b| b.is_ascii_digit()));
        let coloured: Vec<&str> = (0..32).map(|i| &fp[i * 2..i * 2 + 2]).collect();
        prop_assert_eq!(compute(&coloured.join(":").to_lowercase(), &name, &c, &s).unwrap(), code);
    }

    /// The client name is part of the code: another name gives another code. (An 8-digit code can
    /// clash by chance once in a hundred million, which these few hundred cases do not reach.)
    #[test]
    fn another_client_name_gives_another_code(
        fp in "[0-9A-F]{64}", a in ".{0,20}", b in ".{0,20}", c in ".{0,30}", s in ".{0,30}",
    ) {
        prop_assume!(a != b);
        prop_assert_ne!(
            compute(&fp, &a, &c, &s).unwrap(),
            compute(&fp, &b, &c, &s).unwrap()
        );
    }

    /// Where a part ends is part of the input: moving the last byte of one part to the start of
    /// the next changes the code.
    #[test]
    fn moving_a_byte_between_parts_changes_the_code(
        fp in "[0-9A-F]{64}", c in "[a-z]{1,30}", s in "[a-z]{1,30}",
    ) {
        let (head, tail) = c.split_at(c.len() - 1);
        let moved = format!("{tail}{s}");
        prop_assert_ne!(
            compute(&fp, "n", &c, &s).unwrap(),
            compute(&fp, "n", head, &moved).unwrap()
        );
    }

    /// Text that is not 64 hex digits with optional colons gives no code, whatever it holds.
    #[test]
    fn text_that_is_not_a_fingerprint_gives_no_code(text in ".{0,100}") {
        let valid = text.chars().all(|c| c == ':' || c.is_ascii_hexdigit())
            && text.chars().filter(|c| *c != ':').count() == 64;
        prop_assert_eq!(compute(&text, "n", "c", "s").is_some(), valid);
    }

    /// Typed text is the code only when its digits are exactly the code.
    #[test]
    fn a_typed_code_is_the_code_or_not(expected in "[0-9]{8}", typed in ".{0,30}") {
        prop_assert!(is_code(&expected, &expected));
        let digits: String = typed.chars().filter(char::is_ascii_digit).collect();
        prop_assert_eq!(is_code(&expected, &typed), digits == expected);
    }

    /// A client name loses control and format characters, is trimmed, and cleaning it again
    /// changes nothing.
    #[test]
    fn a_client_name_is_clean_and_stays_clean(name in ".{0,200}") {
        let once = clean_client_name(&name);
        prop_assert_eq!(clean_client_name(&once), once.clone());
        prop_assert_eq!(once.trim(), once.as_str());
        prop_assert!(once.chars().all(|c| !c.is_control()));
    }
}
