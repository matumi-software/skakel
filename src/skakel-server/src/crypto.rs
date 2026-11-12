//! The server's certificate.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use time::{Duration, OffsetDateTime};

use crate::store::CertificateRecord;

/// A certificate lasts ten years.
pub(crate) const CERTIFICATE_LIFETIME: Duration = Duration::days(3650);

/// Why something the server makes could not be made.
#[derive(Debug)]
pub struct CryptoError(pub(crate) String);

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CryptoError {}

fn error(what: &str, why: impl std::fmt::Display) -> CryptoError {
    CryptoError(format!("{what}: {why}"))
}

/// A self-signed ECDSA P-256 certificate for `host_name` (and `localhost`), valid from a day ago
/// for ten years. Clients pin its fingerprint and ignore the names.
pub(crate) fn create_certificate(
    host_name: &str,
    organization: &str,
    now: OffsetDateTime,
) -> Result<CertificateRecord, CryptoError> {
    use rcgen::{
        CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair as CertKey,
        KeyUsagePurpose, SanType,
    };

    let key = CertKey::generate().map_err(|e| error("making a certificate key", e))?;
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, host_name);
    params
        .distinguished_name
        .push(DnType::OrganizationName, organization);
    // A name that is not a DNS name is left out; clients pin the fingerprint, not the name.
    if let Ok(name) = host_name.try_into() {
        params.subject_alt_names.push(SanType::DnsName(name));
    }
    if let Ok(name) = "localhost".try_into() {
        params.subject_alt_names.push(SanType::DnsName(name));
    }
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = now - Duration::days(1);
    params.not_after = now + CERTIFICATE_LIFETIME;
    let certificate = params
        .self_signed(&key)
        .map_err(|e| error("signing a certificate", e))?;
    Ok(CertificateRecord {
        certificate: STANDARD.encode(certificate.der().as_ref()),
        private_key: STANDARD.encode(key.serialize_der()),
    })
}

#[cfg(test)]
mod tests {
    use skakel_protocol::fingerprints;

    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    #[test]
    fn a_certificate_lasts_ten_years_and_has_a_fingerprint() {
        let record = create_certificate("pi-lab", "koppel", now()).unwrap();
        let der = STANDARD.decode(&record.certificate).unwrap();

        assert!(fingerprints::normalize(&fingerprints::of_der(&der)).is_some());
        assert!(!record.private_key.is_empty());
        let second = create_certificate("pi-lab", "koppel", now()).unwrap();
        assert_ne!(record.certificate, second.certificate);
    }

    #[test]
    fn a_host_name_that_is_not_ascii_still_makes_a_certificate() {
        assert!(create_certificate("p\u{ef}-lab", "koppel", now()).is_ok());
    }
}
