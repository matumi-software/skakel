//! The Rust client against the Rust server, enrolling with a pairing code and with a server key
//! (`docs/enrollment.md`): what each does when it works, and the ways it must not.

use std::sync::Arc;
use std::time::Duration;

use skakel_client::{
    ClientOptions, EnrollError, Link, Pins, Url, enroll_with_code, enroll_with_key, read_info,
};
use skakel_server::{InMemoryStore, SkakelServer, SkakelServerBuilder};

async fn start() -> SkakelServer {
    SkakelServerBuilder::new("test-app", "1.2.3", Arc::new(InMemoryStore::new()))
        .name("rust-bench")
        .listen("127.0.0.1:0".parse().unwrap())
        .discovery_bind("127.0.0.1".parse().unwrap())
        .discovery_port(0)
        .start()
        .await
        .expect("the server starts")
}

fn address(server: &SkakelServer) -> Url {
    Url::parse(&format!(
        "https://127.0.0.1:{}/",
        server.local_addr().port()
    ))
    .unwrap()
}

fn options() -> ClientOptions {
    ClientOptions::default().request_timeout(Duration::from_secs(10))
}

#[tokio::test]
async fn a_pairing_code_enrols_a_client_once() {
    let server = start().await;
    let code = server
        .enrollment()
        .open_code(Duration::from_secs(60))
        .unwrap()
        .code;

    let enrolled = enroll_with_code(&address(&server), &code, "bench-3", &options())
        .await
        .unwrap();

    assert_eq!(enrolled.server_name, "rust-bench");
    assert!(enrolled.pins.trusts(&server.fingerprint()));
    let clients = server.clients().all();
    assert_eq!(clients.len(), 1);
    assert_eq!(clients[0].name, "bench-3");
    assert_eq!(clients[0].linked_with.as_deref(), Some("code"));
    // The credentials are real: a link built from them is accepted.
    Link::new(
        &address(&server),
        enrolled.pins.clone(),
        enrolled.credentials.clone(),
        options(),
    )
    .unwrap();

    // The code is spent: the same code does nothing a second time, and the server says none is open.
    let again = enroll_with_code(&address(&server), &code, "bench-4", &options()).await;
    assert!(matches!(again, Err(EnrollError::Closed)), "{again:?}");
    assert_eq!(server.clients().all().len(), 1);
}

#[tokio::test]
async fn a_code_can_be_typed_with_a_space_in_it() {
    let server = start().await;
    let code = server
        .enrollment()
        .open_code(Duration::from_secs(60))
        .unwrap()
        .code;
    let typed = format!("{} {}", &code[..4], &code[4..]);

    enroll_with_code(&address(&server), &typed, "bench-3", &options())
        .await
        .unwrap();

    assert_eq!(server.clients().all().len(), 1);
}

#[tokio::test]
async fn a_wrong_code_is_refused_and_three_spend_the_code() {
    let server = start().await;
    let code = server
        .enrollment()
        .open_code(Duration::from_secs(60))
        .unwrap()
        .code;
    let wrong = if code == "00000000" {
        "11111111"
    } else {
        "00000000"
    };

    for _ in 0..3 {
        let result = enroll_with_code(&address(&server), wrong, "bench-3", &options()).await;
        assert!(matches!(result, Err(EnrollError::Refused)), "{result:?}");
    }

    // The code was spent by the third wrong guess, so even the right one now finds nothing open.
    let result = enroll_with_code(&address(&server), &code, "bench-3", &options()).await;
    assert!(matches!(result, Err(EnrollError::Closed)), "{result:?}");
    assert!(server.clients().all().is_empty());
}

#[tokio::test]
async fn with_no_code_open_the_server_says_so() {
    let server = start().await;

    let result = enroll_with_code(&address(&server), "12345678", "bench-3", &options()).await;

    assert!(matches!(result, Err(EnrollError::Closed)), "{result:?}");
}

#[tokio::test]
async fn a_code_that_has_been_closed_does_nothing() {
    let server = start().await;
    let code = server
        .enrollment()
        .open_code(Duration::from_secs(60))
        .unwrap()
        .code;
    server.enrollment().close_code();

    let result = enroll_with_code(&address(&server), &code, "bench-3", &options()).await;

    assert!(matches!(result, Err(EnrollError::Closed)), "{result:?}");
}

#[tokio::test]
async fn a_new_code_replaces_the_old_one() {
    let server = start().await;
    let old = server
        .enrollment()
        .open_code(Duration::from_secs(60))
        .unwrap()
        .code;
    let new = server
        .enrollment()
        .open_code(Duration::from_secs(60))
        .unwrap()
        .code;
    if old == new {
        return;
    }

    let result = enroll_with_code(&address(&server), &old, "bench-3", &options()).await;
    assert!(matches!(result, Err(EnrollError::Refused)), "{result:?}");
    // That was one wrong guess; the new code is still open and works.
    enroll_with_code(&address(&server), &new, "bench-3", &options())
        .await
        .unwrap();
}

#[tokio::test]
async fn a_malformed_code_never_leaves_the_client() {
    let server = start().await;

    for text in ["", "1234567", "123456789", "abcdefgh", "1234 567x"] {
        let result = enroll_with_code(&address(&server), text, "bench-3", &options()).await;
        assert!(
            matches!(result, Err(EnrollError::InvalidCode)),
            "{text:?}: {result:?}"
        );
    }
}

#[tokio::test]
async fn the_server_key_enrols_any_number_of_clients_and_the_servers_info_lists_it() {
    let server = start().await;
    assert_eq!(
        read_info(
            &address(&server),
            &Pins::new(&server.fingerprint()).unwrap(),
            &options()
        )
        .await
        .unwrap()
        .enroll,
        ["code"]
    );
    let key = server.enrollment().key().await.unwrap();
    assert!(key.starts_with("kp1_"));
    assert_eq!(
        read_info(
            &address(&server),
            &Pins::new(&server.fingerprint()).unwrap(),
            &options()
        )
        .await
        .unwrap()
        .enroll,
        ["code", "key"]
    );

    let first = enroll_with_key(&address(&server), &key, "bench-3", &options())
        .await
        .unwrap();
    let second = enroll_with_key(&address(&server), &key, "bench-4", &options())
        .await
        .unwrap();

    assert!(first.pins.trusts(&server.fingerprint()));
    assert_ne!(first.credentials.client_id, second.credentials.client_id);
    let clients = server.clients().all();
    assert_eq!(clients.len(), 2);
    assert!(
        clients
            .iter()
            .all(|c| c.linked_with.as_deref() == Some("key"))
    );
    // The key is still the same key: asking again does not make a new one.
    assert_eq!(server.enrollment().key().await.unwrap(), key);
}

#[tokio::test]
async fn rotating_the_key_spends_the_old_one_and_keeps_enrolled_clients() {
    let server = start().await;
    let old = server.enrollment().key().await.unwrap();
    enroll_with_key(&address(&server), &old, "bench-3", &options())
        .await
        .unwrap();

    let new = server.enrollment().rotate_key().await.unwrap();

    assert_ne!(old, new);
    let result = enroll_with_key(&address(&server), &old, "bench-4", &options()).await;
    assert!(matches!(result, Err(EnrollError::Refused)), "{result:?}");
    enroll_with_key(&address(&server), &new, "bench-4", &options())
        .await
        .unwrap();
    assert_eq!(server.clients().all().len(), 2);
}

#[tokio::test]
async fn a_key_for_another_server_is_refused_before_anything_is_sent() {
    let server = start().await;
    let other = start().await;
    let key_of_other = other.enrollment().key().await.unwrap();
    server.enrollment().key().await.unwrap();

    let result = enroll_with_key(&address(&server), &key_of_other, "bench-3", &options()).await;

    assert!(
        matches!(result, Err(EnrollError::KeyForAnotherServer)),
        "{result:?}"
    );
    assert!(server.clients().all().is_empty());
}

#[tokio::test]
async fn a_bad_key_says_what_is_wrong_with_it() {
    let server = start().await;
    server.enrollment().key().await.unwrap();

    for text in ["hello", "kp1_", "kp1_ZZZZ"] {
        let result = enroll_with_key(&address(&server), text, "bench-3", &options()).await;
        assert!(
            matches!(result, Err(EnrollError::InvalidKey(_))),
            "{text:?}: {result:?}"
        );
    }
}

#[tokio::test]
async fn a_server_with_no_key_made_does_not_take_one() {
    let server = start().await;
    let made_elsewhere = start().await.enrollment().key().await.unwrap();

    let result = enroll_with_key(&address(&server), &made_elsewhere, "bench-3", &options()).await;

    // The server does not list "key" in its info, so the client does not even try.
    assert!(
        matches!(result, Err(EnrollError::NotSupported)),
        "{result:?}"
    );
}

#[tokio::test]
async fn a_name_that_is_empty_is_refused_by_the_client() {
    let server = start().await;
    let code = server
        .enrollment()
        .open_code(Duration::from_secs(60))
        .unwrap()
        .code;

    let result = enroll_with_code(&address(&server), &code, "   ", &options()).await;

    assert!(
        matches!(result, Err(EnrollError::InvalidClientName)),
        "{result:?}"
    );
}

#[tokio::test]
async fn the_key_survives_a_restart_of_the_server_when_the_store_keeps_it() {
    let store = Arc::new(InMemoryStore::new());
    let build = |store: Arc<InMemoryStore>| {
        SkakelServerBuilder::new("test-app", "1.2.3", store)
            .listen("127.0.0.1:0".parse().unwrap())
            .discovery_bind("127.0.0.1".parse().unwrap())
            .discovery_port(0)
    };
    let first = build(store.clone()).start().await.unwrap();
    let key = first.enrollment().key().await.unwrap();
    first.shutdown().await;

    let second = build(store).start().await.unwrap();

    assert_eq!(second.enrollment().key().await.unwrap(), key);
    enroll_with_key(&address(&second), &key, "bench-3", &options())
        .await
        .unwrap();
}

// ---- a stranger in the middle ----

mod middle {
    use std::sync::Arc;

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};
    use skakel_client::Url;

    /// Accepts any certificate: the stranger is not picky about the real server.
    #[derive(Debug)]
    struct Anything(Arc<rustls::crypto::CryptoProvider>);

    impl ServerCertVerifier for Anything {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            m: &[u8],
            c: &CertificateDer<'_>,
            d: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                m,
                c,
                d,
                &self.0.signature_verification_algorithms,
            )
        }
        fn verify_tls13_signature(
            &self,
            m: &[u8],
            c: &CertificateDer<'_>,
            d: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                m,
                c,
                d,
                &self.0.signature_verification_algorithms,
            )
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    /// A TLS-terminating relay with a certificate of its own, in front of `real`: whatever the
    /// client says it hears, and passes on to the real server. Gives the address to use and the
    /// stranger's own fingerprint.
    pub async fn start(real_port: u16) -> (Url, String, tokio::task::JoinHandle<()>) {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let signing = rcgen::KeyPair::generate().unwrap();
        let certificate = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
            .unwrap()
            .self_signed(&signing)
            .unwrap();
        let der = certificate.der().clone();
        let fingerprint = skakel_wire::fingerprints::of_der(&der);
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(signing.serialize_der().into());
        let mut server_config = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der], key)
            .unwrap();
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let mut client_config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Anything(provider)))
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let (acceptor, connector) = (acceptor.clone(), connector.clone());
                tokio::spawn(async move {
                    let Ok(mut near) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let Ok(tcp) = tokio::net::TcpStream::connect(("127.0.0.1", real_port)).await
                    else {
                        return;
                    };
                    let name = ServerName::try_from("localhost").unwrap();
                    let Ok(mut far) = connector.connect(name, tcp).await else {
                        return;
                    };
                    let _ = tokio::io::copy_bidirectional(&mut near, &mut far).await;
                });
            }
        });
        (
            Url::parse(&format!("https://127.0.0.1:{port}/")).unwrap(),
            fingerprint,
            task,
        )
    }
}

#[tokio::test]
async fn a_stranger_in_the_middle_gets_no_credentials_with_a_code() {
    let server = start().await;
    let code = server
        .enrollment()
        .open_code(Duration::from_secs(60))
        .unwrap()
        .code;
    let (address, strangers_fingerprint, relay) = middle::start(server.local_addr().port()).await;
    assert_ne!(strangers_fingerprint, server.fingerprint());

    // The client types the right code, but the certificate it is shown is the stranger's, so its
    // confirmation covers the stranger's fingerprint and the server's check fails.
    let result = enroll_with_code(&address, &code, "bench-3", &options()).await;

    assert!(matches!(result, Err(EnrollError::Refused)), "{result:?}");
    assert!(
        server.clients().all().is_empty(),
        "the server registered a client for the stranger's exchange"
    );
    relay.abort();
}

#[tokio::test]
async fn a_stranger_in_the_middle_gets_no_credentials_with_a_key() {
    let server = start().await;
    let key = server.enrollment().key().await.unwrap();
    let (address, _, relay) = middle::start(server.local_addr().port()).await;

    // The key says which certificate it is for, so the stranger's is refused before the client
    // proves anything.
    let result = enroll_with_key(&address, &key, "bench-3", &options()).await;

    assert!(
        matches!(result, Err(EnrollError::KeyForAnotherServer)),
        "{result:?}"
    );
    assert!(server.clients().all().is_empty());
    relay.abort();
}
