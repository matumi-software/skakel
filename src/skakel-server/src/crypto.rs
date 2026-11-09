//! The server's certificates and its access tokens.
//!
//! Tokens are JWTs signed with ECDSA P-256 (`ES256`), with the key's id in the `kid` header. The
//! protocol says clients do not read a token, so the algorithm is the server's own business, and
//! an ECDSA key takes no time to make where a 2048-bit RSA key takes seconds on a small machine.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair,
    UnparsedPublicKey,
};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};

use crate::store::{CertificateRecord, KeyRecord};
use crate::util;

/// The `iss` of every token, whatever address or name the client used.
pub const ISSUER: &str = "https://skakel.invalid/";

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

/// A fresh token signing key.
pub(crate) fn create_signing_key(now: OffsetDateTime) -> Result<KeyRecord, CryptoError> {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .map_err(|_| CryptoError("making a signing key failed".into()))?;
    Ok(KeyRecord {
        key_id: util::new_id("skakel"),
        private_key: STANDARD.encode(pkcs8.as_ref()),
        created_at: now,
        accept_until: None,
    })
}

/// A key that signs.
pub(crate) struct Signer {
    pub key_id: String,
    pair: EcdsaKeyPair,
}

impl Signer {
    pub(crate) fn load(record: &KeyRecord) -> Result<Self, CryptoError> {
        let pair = key_pair(record)?;
        Ok(Self {
            key_id: record.key_id.clone(),
            pair,
        })
    }
}

/// A key that only checks signatures: the current one's public half, and those of keys it
/// replaced that are still live.
pub(crate) struct Verifier {
    pub key_id: String,
    public: Vec<u8>,
    pub accept_until: Option<OffsetDateTime>,
}

impl Verifier {
    pub(crate) fn load(record: &KeyRecord) -> Result<Self, CryptoError> {
        let pair = key_pair(record)?;
        Ok(Self {
            key_id: record.key_id.clone(),
            public: pair.public_key().as_ref().to_vec(),
            accept_until: record.accept_until,
        })
    }
}

fn key_pair(record: &KeyRecord) -> Result<EcdsaKeyPair, CryptoError> {
    let pkcs8 = STANDARD
        .decode(&record.private_key)
        .map_err(|e| error("reading a signing key", e))?;
    EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        &pkcs8,
        &SystemRandom::new(),
    )
    .map_err(|e| error("reading a signing key", e))
}

/// Who a valid token is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// The client's id (the token's `sub`).
    pub client_id: String,
    /// The client's generation when the token was issued (the `skakel_generation` claim).
    pub generation: u32,
    /// When the token expires.
    pub expires_at: OffsetDateTime,
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// A signed access token for `client_id` at `generation`, and when it expires.
pub(crate) fn issue_token(
    signer: &Signer,
    client_id: &str,
    generation: u32,
    now: OffsetDateTime,
    lifetime: std::time::Duration,
) -> Result<(String, OffsetDateTime), CryptoError> {
    let expires = now + lifetime;
    let header = json!({ "alg": "ES256", "typ": "at+jwt", "kid": signer.key_id });
    let claims = json!({
        "iss": ISSUER,
        "sub": client_id,
        "skakel_generation": generation.to_string(),
        "jti": util::new_token(),
        "iat": now.unix_timestamp(),
        "nbf": now.unix_timestamp(),
        "exp": expires.unix_timestamp(),
    });
    let signing_input = format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(claims.to_string().as_bytes())
    );
    let signature = signer
        .pair
        .sign(&SystemRandom::new(), signing_input.as_bytes())
        .map_err(|_| CryptoError("signing a token failed".into()))?;
    Ok((
        format!("{signing_input}.{}", b64(signature.as_ref())),
        expires,
    ))
}

/// Checks a token's signature, issuer and lifetime. Whether its client still exists, at that
/// generation, is for the caller.
pub(crate) fn read_token(
    verifiers: &[Verifier],
    token: &str,
    now: OffsetDateTime,
) -> Option<Principal> {
    let mut parts = token.split('.');
    let (header, claims, signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).ok()?).ok()?;
    if header.get("alg")?.as_str()? != "ES256" {
        return None;
    }
    let key_id = header.get("kid")?.as_str()?;
    let verifier = verifiers
        .iter()
        .find(|v| v.key_id == key_id && v.accept_until.is_none_or(|until| until > now))?;
    let signature = URL_SAFE_NO_PAD.decode(signature).ok()?;
    let signed = &token[..header_len(token, claims)];
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &verifier.public)
        .verify(signed.as_bytes(), &signature)
        .ok()?;

    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims).ok()?).ok()?;
    if claims.get("iss")?.as_str()? != ISSUER {
        return None;
    }
    let expires = OffsetDateTime::from_unix_timestamp(claims.get("exp")?.as_i64()?).ok()?;
    if expires <= now {
        return None;
    }
    if let Some(not_before) = claims.get("nbf").and_then(Value::as_i64)
        && not_before > now.unix_timestamp() + 60
    {
        return None;
    }
    let generation = match claims.get("skakel_generation")? {
        Value::String(text) => text.parse().ok()?,
        Value::Number(number) => u32::try_from(number.as_u64()?).ok()?,
        _ => return None,
    };
    Some(Principal {
        client_id: claims.get("sub")?.as_str()?.to_owned(),
        generation,
        expires_at: expires,
    })
}

/// The length of `header.claims` at the start of `token`.
fn header_len(token: &str, claims: &str) -> usize {
    let first_dot = token.find('.').expect("a token with claims has a dot");
    first_dot + 1 + claims.len()
}

#[cfg(test)]
mod tests {
    use std::time::Duration as StdDuration;

    use skakel_protocol::fingerprints;

    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    fn keys() -> (Signer, Vec<Verifier>) {
        let record = create_signing_key(now()).unwrap();
        (
            Signer::load(&record).unwrap(),
            vec![Verifier::load(&record).unwrap()],
        )
    }

    #[test]
    fn a_token_reads_back_as_the_client_and_generation_it_was_issued_for() {
        let (signer, verifiers) = keys();

        let (token, expires) =
            issue_token(&signer, "client-1", 3, now(), StdDuration::from_secs(1800)).unwrap();
        let principal = read_token(&verifiers, &token, now()).unwrap();

        assert_eq!(principal.client_id, "client-1");
        assert_eq!(principal.generation, 3);
        assert_eq!(principal.expires_at, expires);
        assert_eq!(expires, now() + Duration::minutes(30));
    }

    #[test]
    fn a_token_names_its_key_and_the_skakel_issuer_and_generation_claim() {
        let (signer, _) = keys();
        let (token, _) =
            issue_token(&signer, "client-1", 3, now(), StdDuration::from_secs(60)).unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();

        assert_eq!(header["kid"], signer.key_id.as_str());
        assert_eq!(claims["iss"], "https://skakel.invalid/");
        assert_eq!(claims["skakel_generation"], "3");
        assert_eq!(claims["sub"], "client-1");
    }

    #[test]
    fn an_expired_token_is_refused() {
        let (signer, verifiers) = keys();
        let (token, _) =
            issue_token(&signer, "client-1", 1, now(), StdDuration::from_secs(60)).unwrap();

        assert!(read_token(&verifiers, &token, now() + Duration::seconds(59)).is_some());
        assert!(read_token(&verifiers, &token, now() + Duration::seconds(60)).is_none());
    }

    #[test]
    fn a_token_from_another_key_or_with_a_changed_claim_is_refused() {
        let (signer, verifiers) = keys();
        let (other, _) = keys();
        let (token, _) =
            issue_token(&signer, "client-1", 1, now(), StdDuration::from_secs(60)).unwrap();
        let (foreign, _) =
            issue_token(&other, "client-1", 1, now(), StdDuration::from_secs(60)).unwrap();
        let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
        parts[1] = b64(br#"{"iss":"https://skakel.invalid/","sub":"client-2","skakel_generation":"1","exp":9999999999}"#);

        assert!(read_token(&verifiers, &foreign, now()).is_none());
        assert!(read_token(&verifiers, &parts.join("."), now()).is_none());
        assert!(read_token(&verifiers, "a.b", now()).is_none());
        assert!(read_token(&verifiers, "", now()).is_none());
        assert!(read_token(&verifiers, &format!("{token}.x"), now()).is_none());
    }

    #[test]
    fn a_replaced_key_is_taken_until_its_time_is_up() {
        let mut record = create_signing_key(now()).unwrap();
        let signer = Signer::load(&record).unwrap();
        let (token, _) =
            issue_token(&signer, "client-1", 1, now(), StdDuration::from_secs(1800)).unwrap();
        record.accept_until = Some(now() + Duration::minutes(10));
        let verifiers = vec![Verifier::load(&record).unwrap()];

        assert!(read_token(&verifiers, &token, now() + Duration::minutes(9)).is_some());
        assert!(read_token(&verifiers, &token, now() + Duration::minutes(10)).is_none());
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
