//! HTTP that trusts exactly the certificates a server is pinned to and nothing else. Self-signed is
//! fine; that is the point of pinning. The pins are read at each handshake, so a client made before
//! a handover trusts the new certificate once the link learned it.
//!
//! The plain HTTPS client is in [`crate::request`]; this has the pins' TLS, the connector both it
//! and the gRPC connections use, and the address helpers.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use std::net::{IpAddr, SocketAddr};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, ring};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};
use skakel_wire::fingerprints;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::{Host, Url};

use crate::failure::{Error, FailureKind};
use crate::pins::Pins;

/// How long opening a TCP connection may take.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The most of any plain HTTPS answer the library reads: info, pairing and tokens are all far
/// smaller.
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

/// A TLS configuration that trusts the pins and nothing else. `presented`, when given, is told the
/// fingerprint of each certificate a handshake trusted.
pub(crate) fn tls_config(pins: PinsFn, presented: Option<Presented>) -> rustls::ClientConfig {
    let provider = Arc::new(ring::default_provider());
    let verifier = PinnedVerifier {
        pins,
        presented,
        algorithms: provider.signature_verification_algorithms,
    };
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("the ring provider speaks the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth()
}

/// Opens a TCP connection to `address` within ten seconds and runs TLS over it with `config`. The
/// handshake trusts the pins in `config` and nothing else, so what comes back is a connection to a
/// holder of a pinned certificate.
pub(crate) async fn connect_tls(
    address: &Url,
    config: Arc<rustls::ClientConfig>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Error> {
    let port = address.port_or_known_default().unwrap_or(443);
    let (host, ip) = match address.host() {
        Some(Host::Ipv4(ip)) => (ip.to_string(), Some(IpAddr::V4(ip))),
        Some(Host::Ipv6(ip)) => (ip.to_string(), Some(IpAddr::V6(ip))),
        Some(Host::Domain(name)) => (name.to_owned(), None),
        None => return Err(Error::of(FailureKind::Unreachable)),
    };
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, async {
        match ip {
            Some(ip) => TcpStream::connect(SocketAddr::new(ip, port)).await,
            None => TcpStream::connect((host.as_str(), port)).await,
        }
    })
    .await
    .map_err(Error::from_cause)?
    .map_err(Error::from_cause)?;
    let _ = tcp.set_nodelay(true);
    let name = match ip {
        Some(ip) => ServerName::IpAddress(ip.into()),
        None => ServerName::try_from(host).map_err(Error::from_cause)?,
    };
    TlsConnector::from(config)
        .connect(name, tcp)
        .await
        .map_err(Error::from_cause)
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
