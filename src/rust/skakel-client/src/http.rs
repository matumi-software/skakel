//! HTTP that trusts exactly the certificates a server is pinned to and nothing else. Self-signed is
//! fine; that is the point of pinning. The pins are read at each handshake, so a client made before
//! a handover trusts the new certificate once the link learned it.
//!
//! A Skakel server is on the local network, so the client never goes through a proxy: a system proxy
//! would see every request's address, and could not reach most LAN addresses anyway. A redirect is
//! not followed, and no connection is kept for another request, so one made under a pin the link has
//! since dropped never stays in use.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::Url;
use reqwest::redirect::Policy;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, ring};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};
use serde::de::DeserializeOwned;
use skakel_protocol::fingerprints;

use crate::failure::{Error, FailureKind, StatusError, bad_answer};
use crate::pins::Pins;

/// How long opening a TCP connection may take.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The most of any answer the library reads: info, pairing, tokens, hello and the hub's negotiation
/// are all far smaller.
pub(crate) const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// The pins to trust, read at each handshake.
pub(crate) type PinsFn = Arc<dyn Fn() -> Pins + Send + Sync>;

/// The fingerprint of the certificate the last handshake trusted.
pub(crate) type Presented = Arc<Mutex<Option<String>>>;

pub(crate) fn presented() -> Presented {
    Arc::new(Mutex::new(None))
}

pub(crate) fn last_presented(presented: &Presented) -> Option<String> {
    presented.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Trusts a certificate when its SHA-256 fingerprint is a pinned one, whatever name it was reached
/// by and whoever signed it. The handshake's signature is still checked against the certificate's
/// key, so only the holder of the pinned certificate's key passes.
struct PinnedVerifier {
    pins: PinsFn,
    presented: Option<Presented>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl std::fmt::Debug for PinnedVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinnedVerifier").finish_non_exhaustive()
    }
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if !(self.pins)().trusts_certificate(end_entity.as_ref()) {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        if let Some(presented) = &self.presented {
            *presented.lock().unwrap_or_else(|e| e.into_inner()) =
                Some(fingerprints::of_der(end_entity.as_ref()));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// An HTTP client over the pins. `presented`, when given, is told the fingerprint of each
/// certificate a handshake trusted.
pub(crate) fn client(pins: PinsFn, presented: Option<Presented>) -> reqwest::Client {
    let provider = Arc::new(ring::default_provider());
    let verifier = PinnedVerifier {
        pins,
        presented,
        algorithms: provider.signature_verification_algorithms,
    };
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("the ring provider speaks the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    reqwest::Client::builder()
        .tls_backend_preconfigured(config)
        .no_proxy()
        .redirect(Policy::none())
        .pool_max_idle_per_host(0)
        .connect_timeout(CONNECT_TIMEOUT)
        .https_only(true)
        .http1_only()
        .build()
        .expect("a client with this configuration always builds")
}

/// An HTTP client pinned to fixed pins.
pub(crate) fn client_for(pins: Pins) -> reqwest::Client {
    client(Arc::new(move || pins.clone()), None)
}

/// A server's base address: HTTPS, scheme, host and port only.
pub(crate) fn base_address(address: &Url) -> Result<Url, Error> {
    if address.scheme() != "https" || address.host().is_none() {
        return Err(Error::caused(
            FailureKind::Unreachable,
            crate::failure::BadAnswer(
                "A Skakel server's address is an absolute https:// address.".to_owned(),
            ),
        ));
    }
    let mut base = address.clone();
    base.set_path("/");
    base.set_query(None);
    base.set_fragment(None);
    let _ = base.set_username("");
    let _ = base.set_password(None);
    Ok(base)
}

/// True for an absolute HTTPS address at the server's host and port.
pub(crate) fn is_at(address: &Url, server: &Url) -> bool {
    address.scheme() == "https"
        && address.host_str().map(str::to_ascii_lowercase)
            == server.host_str().map(str::to_ascii_lowercase)
        && address.port_or_known_default() == server.port_or_known_default()
}

/// `host:port`, lower case, to tell addresses apart.
pub(crate) fn authority(address: &Url) -> String {
    format!(
        "{}:{}",
        address.host_str().unwrap_or_default().to_ascii_lowercase(),
        address.port_or_known_default().unwrap_or(443)
    )
}

/// The whole body, or an error when it is longer than the client reads.
pub(crate) async fn read_limited(mut response: reqwest::Response) -> Result<Vec<u8>, Error> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(bad_answer("The answer is longer than the client reads."));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(Error::from_cause)? {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(bad_answer("The answer is longer than the client reads."));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// An error unless the status is 2xx.
pub(crate) fn ensure_success(response: &reqwest::Response) -> Result<(), Error> {
    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(Error::from_cause(StatusError(status.as_u16())))
    }
}

/// The body of a successful answer as JSON.
pub(crate) async fn read_json<T: DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, Error> {
    ensure_success(&response)?;
    let body = read_limited(response).await?;
    serde_json::from_slice(&body).map_err(Error::from_cause)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_address_keeps_scheme_host_and_port_only() {
        let base =
            base_address(&Url::parse("https://user:pw@pi-lab:5240/a/b?c#d").unwrap()).unwrap();

        assert_eq!(base.as_str(), "https://pi-lab:5240/");
    }

    #[test]
    fn base_address_refuses_plain_http() {
        assert!(base_address(&Url::parse("http://pi-lab:5240/").unwrap()).is_err());
    }

    #[test]
    fn is_at_compares_host_and_port_over_https() {
        let server = Url::parse("https://PI-lab:5240/").unwrap();

        assert!(is_at(
            &Url::parse("https://pi-lab:5240/x").unwrap(),
            &server
        ));
        assert!(!is_at(
            &Url::parse("https://pi-lab:5241/").unwrap(),
            &server
        ));
        assert!(!is_at(&Url::parse("https://other:5240/").unwrap(), &server));
        assert!(!is_at(&Url::parse("http://pi-lab:5240/").unwrap(), &server));
    }
}
