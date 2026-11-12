//! What a client holds for one server: the certificates it trusts and the credentials it signs in
//! with. The app keeps both beside the server's address.

use std::fmt;

use skakel_protocol::fingerprints;
use zeroize::Zeroize;

/// The certificates a client trusts for one server: the pinned one and, while the server hands over
/// to a new certificate, the next one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pins {
    fingerprint: String,
    next_fingerprint: Option<String>,
}

/// A fingerprint that is not 64 hex digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidFingerprint;

impl fmt::Display for InvalidFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("A fingerprint is 64 hex digits.")
    }
}

impl std::error::Error for InvalidFingerprint {}

impl Pins {
    /// Pins a server's certificate. The fingerprint is 64 hex digits, with or without colons.
    pub fn new(fingerprint: &str) -> Result<Self, InvalidFingerprint> {
        Self::with_next(fingerprint, None)
    }

    /// Pins a server's certificate and the one it said it will switch to.
    pub fn with_next(fingerprint: &str, next: Option<&str>) -> Result<Self, InvalidFingerprint> {
        let fingerprint = fingerprints::normalize(fingerprint).ok_or(InvalidFingerprint)?;
        let next = match next {
            None => None,
            Some(next) => Some(fingerprints::normalize(next).ok_or(InvalidFingerprint)?),
        };
        // A next certificate that is the pinned one is no handover.
        let next = next.filter(|next| !fingerprints::are_equal(&fingerprint, next));
        Ok(Self {
            fingerprint,
            next_fingerprint: next,
        })
    }

    /// The pinned fingerprint, in colon form.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The certificate the server will switch to, trusted as well until then.
    pub fn next_fingerprint(&self) -> Option<&str> {
        self.next_fingerprint.as_deref()
    }

    /// True when the certificate (its DER bytes) is the pinned one or the next one.
    pub fn trusts_certificate(&self, der: &[u8]) -> bool {
        fingerprints::matches_any_der(
            der,
            std::iter::once(self.fingerprint.as_str()).chain(self.next_fingerprint.as_deref()),
        )
    }

    /// True when the fingerprint, in any form, is the pinned one or the next one.
    pub fn trusts(&self, fingerprint: &str) -> bool {
        fingerprints::are_equal(fingerprint, &self.fingerprint)
            || self
                .next_fingerprint
                .as_deref()
                .is_some_and(|next| fingerprints::are_equal(fingerprint, next))
    }

    /// What the server said about its certificates, over a connection pinned to one of these. When
    /// it now presents the next one, that becomes the pinned one; either way the next one is what it
    /// says, or none. A statement about a certificate these pins do not know changes nothing.
    pub(crate) fn with_server_certificates(&self, fingerprint: &str, next: Option<&str>) -> Self {
        let current = if fingerprints::are_equal(fingerprint, &self.fingerprint) {
            Some(self.fingerprint.as_str())
        } else if self
            .next_fingerprint
            .as_deref()
            .is_some_and(|n| fingerprints::are_equal(fingerprint, n))
        {
            self.next_fingerprint.as_deref()
        } else {
            None
        };
        match current {
            Some(current) => Self::with_next(current, next).unwrap_or_else(|_| self.clone()),
            None => self.clone(),
        }
    }
}

/// What a client signs in to one server with. Pairing hands them over; the app keeps them, and the
/// secret only where it keeps secrets.
///
/// The secret is overwritten with zeros when a `Credentials` is dropped, and so is each clone's. That
/// is best effort: copies the app made of the string itself, and buffers a `String` left behind when
/// it grew, are not reached. Because of the wipe, the fields cannot be moved out of a `Credentials`
/// (destructuring it by value does not compile); clone them or read them by reference.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    /// The client's ID on that server.
    pub client_id: String,
    /// The client's secret on that server.
    pub client_secret: String,
}

impl Credentials {
    /// Credentials from an ID and a secret.
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
        }
    }
}

impl Credentials {
    fn wipe(&mut self) {
        self.client_secret.zeroize();
    }
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// The client ID, never the secret, so a log line cannot leak it.
impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(pair: &str) -> String {
        vec![pair; 32].join(":")
    }

    #[test]
    fn new_normalises_and_refuses_what_is_not_a_fingerprint() {
        assert_eq!(Pins::new(&"ab".repeat(32)).unwrap().fingerprint(), fp("AB"));
        assert_eq!(Pins::new("AB"), Err(InvalidFingerprint));
        assert_eq!(
            Pins::with_next(&fp("AB"), Some("nope")),
            Err(InvalidFingerprint)
        );
    }

    #[test]
    fn a_next_certificate_equal_to_the_pinned_one_is_dropped() {
        let pins = Pins::with_next(&fp("AB"), Some(&"ab".repeat(32))).unwrap();

        assert_eq!(pins.next_fingerprint(), None);
    }

    #[test]
    fn trusts_the_pinned_and_the_next_and_nothing_else() {
        let pins = Pins::with_next(&fp("AB"), Some(&fp("CD"))).unwrap();

        assert!(pins.trusts(&fp("AB")));
        assert!(pins.trusts(&"cd".repeat(32)));
        assert!(!pins.trusts(&fp("EF")));
        assert!(!pins.trusts(""));
    }

    #[test]
    fn a_statement_about_the_pinned_certificate_sets_the_next_one() {
        let pins = Pins::new(&fp("AB")).unwrap();

        let after = pins.with_server_certificates(&fp("AB"), Some(&fp("CD")));

        assert_eq!(after, Pins::with_next(&fp("AB"), Some(&fp("CD"))).unwrap());
        assert_eq!(after.with_server_certificates(&fp("AB"), None), pins);
    }

    #[test]
    fn a_statement_that_the_next_certificate_is_presented_switches_to_it() {
        let pins = Pins::with_next(&fp("AB"), Some(&fp("CD"))).unwrap();

        let after = pins.with_server_certificates(&fp("CD"), None);

        assert_eq!(after, Pins::new(&fp("CD")).unwrap());
    }

    #[test]
    fn a_statement_about_an_unknown_certificate_changes_nothing() {
        let pins = Pins::with_next(&fp("AB"), Some(&fp("CD"))).unwrap();

        assert_eq!(
            pins.with_server_certificates(&fp("EF"), Some(&fp("01"))),
            pins
        );
    }

    #[test]
    fn wiping_credentials_clears_the_secret_and_keeps_the_id() {
        let mut credentials = Credentials::new("c1", "hunter2");
        let clone = credentials.clone();

        credentials.wipe();

        assert!(credentials.client_secret.is_empty());
        assert_eq!(credentials.client_id, "c1");
        // A clone holds its own copy and is wiped on its own drop.
        assert_eq!(clone.client_secret, "hunter2");
    }

    #[test]
    fn credentials_never_show_the_secret() {
        let text = format!("{:?}", Credentials::new("c1", "hunter2"));

        assert!(text.contains("c1"));
        assert!(!text.contains("hunter2"));
    }
}
