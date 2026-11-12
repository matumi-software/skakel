//! What the client does against a hostile or broken peer: an info answer that is too big, too
//! generous with versions or never finishes, a control call that answers with garbage, and a flood
//! of discovery answers. None of it may hang, panic or grow without bound.

mod common;

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{free_udp, within};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::json;
use skakel_client::{
    Browser, BrowserOptions, ClientOptions, Credentials, FailureKind, Link, LinkState, Pins, Url,
    read_info,
};
use skakel_wire::SkakelApp;
use skakel_wire::discovery::{DiscoveryAnswer, MAX_ENTRIES, MAX_ENTRIES_PER_ADDRESS};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_rustls::server::TlsStream;

/// A TLS server with a certificate of its own that hands every connection to `serve`.
struct Hostile {
    port: u16,
    fingerprint: String,
    task: tokio::task::JoinHandle<()>,
}

impl Hostile {
    async fn start<F, Fut>(h2: bool, serve: F) -> Self
    where
        F: Fn(TlsStream<TcpStream>) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let signing = rcgen::KeyPair::generate().unwrap();
        let certificate = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
            .unwrap()
            .self_signed(&signing)
            .unwrap();
        let der = certificate.der().clone();
        let fingerprint = skakel_wire::fingerprints::of_der(&der);
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(signing.serialize_der().into());
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der], key)
        .unwrap();
        config.alpn_protocols = if h2 {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        } else {
            vec![b"http/1.1".to_vec()]
        };
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let (acceptor, serve) = (acceptor.clone(), serve.clone());
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(tcp).await {
                        serve(tls).await;
                    }
                });
            }
        });
        Self {
            port,
            fingerprint,
            task,
        }
    }

    fn address(&self) -> Url {
        Url::parse(&format!("https://127.0.0.1:{}/", self.port)).unwrap()
    }

    fn pins(&self) -> Pins {
        Pins::new(&self.fingerprint).unwrap()
    }
}

impl Drop for Hostile {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Reads one HTTP/1.1 request head.
async fn read_head(tls: &mut TlsStream<TcpStream>) -> bool {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match tls.read(&mut byte).await {
            Ok(1) => head.push(byte[0]),
            _ => return false,
        }
    }
    true
}

fn info(versions: &[i32]) -> String {
    json!({ "name": "elsewhere", "app": { "id": "test-app", "version": "1.0.0" }, "versions": versions })
        .to_string()
}

async fn answer_with(mut tls: TlsStream<TcpStream>, body: Vec<u8>) {
    if !read_head(&mut tls).await {
        return;
    }
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = tls.write_all(head.as_bytes()).await;
    let _ = tls.write_all(&body).await;
    let _ = tls.shutdown().await;
}

#[tokio::test]
async fn an_info_answer_over_the_size_cap_is_refused() {
    let big = {
        let mut body = info(&[2]).into_bytes();
        body.extend(std::iter::repeat_n(b' ', 200 * 1024));
        body
    };
    let server = Hostile::start(false, move |tls| answer_with(tls, big.clone())).await;

    let result = within(
        Duration::from_secs(10),
        read_info(&server.address(), &server.pins(), &ClientOptions::default()),
    )
    .await;

    assert_eq!(
        result.unwrap_err().kind(),
        FailureKind::UnexpectedAnswer,
        "200 KiB is not a Skakel info answer"
    );
}

#[tokio::test]
async fn an_info_answer_that_lists_too_many_versions_is_refused() {
    let many: Vec<i32> = (1..=200).collect();
    let body = info(&many).into_bytes();
    let server = Hostile::start(false, move |tls| answer_with(tls, body.clone())).await;

    let result = within(
        Duration::from_secs(10),
        read_info(&server.address(), &server.pins(), &ClientOptions::default()),
    )
    .await;

    assert_eq!(
        result.unwrap_err().kind(),
        FailureKind::UnexpectedAnswer,
        "no more than 8 versions"
    );
}

#[tokio::test]
async fn an_info_answer_that_stops_arriving_ends_at_the_request_timeout() {
    let server = Hostile::start(false, |mut tls| async move {
        if !read_head(&mut tls).await {
            return;
        }
        // The head says 500 bytes and ten arrive; then the server sits on the connection.
        let _ = tls
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n{\"name\":\"a\"")
            .await;
        tokio::time::sleep(Duration::from_secs(60)).await;
    })
    .await;
    let options = ClientOptions::default().request_timeout(Duration::from_secs(1));

    let started = Instant::now();
    let result = within(
        Duration::from_secs(10),
        read_info(&server.address(), &server.pins(), &options),
    )
    .await;

    assert!(
        matches!(
            result.unwrap_err().kind(),
            FailureKind::Unreachable | FailureKind::ConnectionLost | FailureKind::UnexpectedAnswer
        ),
        "a stalled answer is a failure, not a certificate problem"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "gave up after {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_control_call_that_answers_with_garbage_never_connects_and_the_link_still_stops() {
    let server = Hostile::start(true, |tls| async move {
        let service = hyper::service::service_fn(
            |request: hyper::Request<hyper::body::Incoming>| async move {
                let path = request.uri().path().to_owned();
                let response = match path.as_str() {
                "/skakel/info" => hyper::Response::builder()
                    .header("content-type", "application/json")
                    .body(Full::new(Bytes::from(info(&[2]))))
                    .unwrap(),
                "/skakel/v2/token" => hyper::Response::builder()
                    .header("content-type", "application/json")
                    .body(Full::new(Bytes::from(
                        json!({ "access_token": "t", "token_type": "Bearer", "expires_in": 1800 })
                            .to_string(),
                    )))
                    .unwrap(),
                _ => {
                    // A gRPC frame that claims four GiB, then a few bytes of nothing.
                    let mut frame = vec![0u8, 0xFF, 0xFF, 0xFF, 0xFF];
                    frame.extend_from_slice(&[1, 2, 3]);
                    hyper::Response::builder()
                        .header("content-type", "application/grpc")
                        .body(Full::new(Bytes::from(frame)))
                        .unwrap()
                }
            };
                Ok::<_, std::convert::Infallible>(response)
            },
        );
        let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(tls), service)
            .await;
    })
    .await;
    let options = ClientOptions::default().request_timeout(Duration::from_secs(2));
    let link = Link::new(
        &server.address(),
        server.pins(),
        Credentials::new("client", "secret"),
        options,
    )
    .unwrap();
    let statuses = common::record_status(&link);

    link.start();
    tokio::time::sleep(Duration::from_secs(4)).await;

    assert!(
        statuses
            .seen()
            .iter()
            .all(|s| s.state != LinkState::Connected),
        "a control call with no certificates is not a connection: {:?}",
        statuses.seen()
    );
    within(Duration::from_secs(10), link.stop()).await;
}

/// Answers every probe it gets with `answers` made up answers from sockets on many loopback
/// addresses, and with junk, to the address the probe came from.
fn flood(udp: u16, addresses: u8, per_address: u32) -> tokio::task::JoinHandle<()> {
    let listener = std::net::UdpSocket::bind(("127.0.0.1", udp)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let listener = UdpSocket::from_std(listener).unwrap();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 2048];
        loop {
            let Ok((_, from)) = listener.recv_from(&mut buffer).await else {
                return;
            };
            let mut n = 0u32;
            for host in 1..=addresses {
                let socket = UdpSocket::bind(format!("127.0.0.{}:0", host.max(1)))
                    .await
                    .unwrap();
                for _ in 0..per_address {
                    n += 1;
                    let answer = skakel_wire::discovery::create_answer(&DiscoveryAnswer {
                        name: format!("server {n}"),
                        port: 5240,
                        fingerprint: format!("{n:064X}"),
                        app: SkakelApp {
                            id: "test-app".into(),
                            version: "1.0.0".into(),
                        },
                        versions: vec![2],
                    })
                    .unwrap();
                    let _ = socket.send_to(&answer, from).await;
                    let _ = socket.send_to(&[0xFFu8; 300], from).await;
                }
            }
        }
    })
}

#[tokio::test]
async fn a_flood_of_answers_from_one_address_keeps_eight_entries_and_the_browser_alive() {
    let udp = free_udp();
    let sender = flood(udp, 1, 300);
    let browser = Browser::new(
        BrowserOptions::new(udp)
            .probe_targets(vec![SocketAddr::from(([127, 0, 0, 1], udp))])
            .probe_interval(Duration::from_millis(300)),
    );
    browser.start().await.unwrap();

    tokio::time::sleep(Duration::from_secs(2)).await;

    assert_eq!(browser.entries().len(), MAX_ENTRIES_PER_ADDRESS);
    assert!(browser.is_browsing());
    browser.stop();
    sender.abort();
}

#[tokio::test]
async fn a_flood_of_answers_from_many_addresses_keeps_the_list_at_its_cap() {
    let udp = free_udp();
    let sender = flood(udp, 100, 3);
    let browser = Browser::new(
        BrowserOptions::new(udp)
            .probe_targets(vec![SocketAddr::from(([127, 0, 0, 1], udp))])
            .probe_interval(Duration::from_millis(300)),
    );
    browser.start().await.unwrap();

    tokio::time::sleep(Duration::from_secs(2)).await;

    let entries = browser.entries();
    assert!(
        entries.len() <= MAX_ENTRIES,
        "{} entries over the cap of {MAX_ENTRIES}",
        entries.len()
    );
    assert!(entries.len() > MAX_ENTRIES_PER_ADDRESS, "{}", entries.len());
    assert!(browser.is_browsing());
    browser.stop();
    sender.abort();
}
