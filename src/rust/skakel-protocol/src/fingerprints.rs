//! Certificate fingerprints: the SHA-256 of the certificate, written as 32 hex pairs separated by
//! colons, such as `3F:9A:...`. Two fingerprints compare by their hex digits alone.
//!
//! A certificate is its DER bytes here; parsing certificates is the TLS library's job.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// How many hex digits a fingerprint has.
pub const HEX_DIGITS: usize = 64;

/// The fingerprint of a certificate given as its DER bytes, in colon form (uppercase).
pub fn of_der(certificate: &[u8]) -> String {
    let hash = Sha256::digest(certificate);
    let mut text = String::with_capacity(HEX_DIGITS + 31);
    for (i, byte) in hash.iter().enumerate() {
        if i > 0 {
            text.push(':');
        }
        text.push_str(&format!("{byte:02X}"));
    }
    text
}

/// The fingerprint in colon form, uppercase, or `None` unless the text is exactly 64 hex digits,
/// with or without colons.
pub fn normalize(text: &str) -> Option<String> {
    if text.chars().any(|c| c != ':' && !c.is_ascii_hexdigit()) {
        return None;
    }
    let hex: String = text
        .chars()
        .filter(|c| *c != ':')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if hex.len() != HEX_DIGITS {
        return None;
    }
    let pairs: Vec<&str> = (0..32).map(|i| &hex[i * 2..i * 2 + 2]).collect();
    Some(pairs.join(":"))
}

/// True when both are the same fingerprint, by their hex digits alone, in constant time. Empty and
/// blank text matches nothing.
pub fn are_equal(a: &str, b: &str) -> bool {
    if a.trim().is_empty() || b.trim().is_empty() {
        return false;
    }
    digits(a).ct_eq(&digits(b)).into()
}

/// True when the certificate (its DER bytes) has the pinned fingerprint.
pub fn matches_der(certificate: &[u8], pinned: &str) -> bool {
    are_equal(&of_der(certificate), pinned)
}

/// True when the certificate has any of the pinned fingerprints. Empty ones match nothing.
pub fn matches_any_der<'a>(certificate: &[u8], pinned: impl IntoIterator<Item = &'a str>) -> bool {
    let fingerprint = of_der(certificate);
    pinned.into_iter().any(|p| are_equal(&fingerprint, p))
}

/// The hex digits of a fingerprint, uppercase, with everything else left out.
fn digits(fingerprint: &str) -> Vec<u8> {
    fingerprint
        .bytes()
        .filter(u8::is_ascii_hexdigit)
        .map(|b| b.to_ascii_uppercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    /// The same self-signed certificate and fingerprint `FingerprintsTests` in .NET pins.
    const CERTIFICATE: &str = "MIIBHzCBxqADAgECAgh4tnYgc2q+xzAKBggqhkjOPQQDAjAWMRQwEgYDVQQDEwtza2FrZWwtdGVzdDAeFw0yNjAxMDEwMDAwMDBaFw0zNjAxMDEwMDAwMDBaMBYxFDASBgNVBAMTC3NrYWtlbC10ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9Qp6QPUFM5MDGOSKS+mZV+AmOGS49E487on6Ry4gB9Lt7LUai6B5Qk9QPOPWkvtq6zVkHClbtNRx33Iv7r3tGjAKBggqhkjOPQQDAgNIADBFAiAfWudN9OBxLvO/v3O5wKuXDbds95mmUjp56KAfnY7wBgIhALoHuJGsHQ4Pus6MSaBZwRKhh6VsTecKPoCMXlJ17VLy";
    const FINGERPRINT: &str = "78:8D:08:D5:45:DB:3E:4C:51:D3:8A:4D:E2:7F:63:F0:72:1E:0B:D8:57:62:6A:E4:DB:22:B9:76:17:C5:6B:83";

    fn certificate() -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(CERTIFICATE)
            .unwrap()
    }

    #[test]
    fn of_der_gives_the_fingerprint_dotnet_gives() {
        assert_eq!(of_der(&certificate()), FINGERPRINT);
    }

    #[test]
    fn of_der_is_the_sha256_of_the_bytes_in_colon_form() {
        assert_eq!(
            of_der(b"abc"),
            "BA:78:16:BF:8F:01:CF:EA:41:41:40:DE:5D:AE:22:23:B0:03:61:A3:96:17:7A:9C:B4:10:FF:61:F2:00:15:AD"
        );
    }

    #[test]
    fn normalize_gives_the_colon_form_or_none() {
        let colon = vec!["AA"; 32].join(":");

        assert_eq!(normalize(&"a".repeat(64)), Some(colon.clone()));
        assert_eq!(normalize(&vec!["aa"; 32].join(":")), Some(colon));
        assert_eq!(normalize(&"a".repeat(62)), None);
        assert_eq!(normalize(&"a".repeat(66)), None);
        assert_eq!(normalize(&"g".repeat(64)), None);
        assert_eq!(normalize(""), None);
    }

    #[test]
    fn are_equal_compares_by_hex_digits_alone() {
        let colon = vec!["AB"; 32].join(":");
        let plain = "ba".repeat(32);
        let shifted = format!("a{}b", "ba".repeat(31));

        assert!(are_equal(&colon, &shifted));
        assert!(!are_equal(&colon, &plain));
        assert!(!are_equal(&colon, &colon.replace("AB", "AC")));
        assert!(!are_equal(&colon, ""));
        assert!(!are_equal("", ""));
        assert!(!are_equal("  ", "  "));
    }

    #[test]
    fn matches_takes_the_certificate_s_own_fingerprint_and_no_other() {
        let certificate = certificate();
        let lower = FINGERPRINT.to_ascii_lowercase().replace(':', "");

        assert!(matches_der(&certificate, &lower));
        assert!(!matches_der(&certificate, &vec!["00"; 32].join(":")));
        assert!(matches_any_der(&certificate, ["", FINGERPRINT]));
        assert!(!matches_any_der(&certificate, [""]));
        assert!(!matches_any_der(&certificate, []));
    }
}
