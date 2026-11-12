//! The server's gRPC side over TLS on loopback, as a client sees it: one port for HTTPS and gRPC,
//! the control channel, the streams, the app's own services, the refusals with their reasons, and
//! the keep-alive. The calls are made with the generated clients over HTTP/2 connections of the
//! tests' own, so they do not depend on the Rust client.

mod common;

use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use common::greeter::{self, GreetRequest, WatchRequest};
use common::*;
use prost::Message as _;
use prost::bytes::Bytes;
use skakel_proto::v2::{
    ClosingReason, ConnectRequest, HelloRequest, NextCertificateReceived, OpenRequest,
    SerialClientMessage, SerialServerMessage, connect_request, connect_response, open_request,
    open_response, serial_client_message, serial_server_message,
};
use skakel_wire::fingerprints;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_stream::wrappers::ReceiverStream;
use tonic::Code;
use tonic::codegen::http;

fn hello() -> HelloRequest {
    HelloRequest {}
}

// ---- hello and tokens ----

#[tokio::test]
async fn hello_answers_the_servers_name_and_the_client_the_token_is_for() {
    let server = start().await;
    let (client, token) = client_with_token(&server, "bench-1").await;
    let connection = grpc(&server).await;

    let answer = control(&connection)
        .hello(with_token(hello(), &token))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(answer.server, NAME);
    assert_eq!(answer.client_id, client.client_id);
}

#[tokio::test]
async fn hello_refuses_no_token_a_bad_one_and_those_of_a_rotated_or_revoked_client() {
    let server = start().await;
    let (client, token) = client_with_token(&server, "bench-1").await;
    let connection = grpc(&server).await;
    let mut control = control(&connection);

    let none = control.hello(hello()).await.unwrap_err();
    let bad = control
        .hello(with_token(hello(), "a.b.c"))
        .await
        .unwrap_err();
    let secret = server
        .clients()
        .rotate_secret(&client.client_id)
        .await
        .unwrap()
        .unwrap();
    let rotated = control
        .hello(with_token(hello(), &token))
        .await
        .unwrap_err();
    let renewed = token_for(&server, &client.client_id, &secret).await;
    let after_renewal = control.hello(with_token(hello(), &renewed)).await;
    server.clients().revoke(&client.client_id).await.unwrap();
    let revoked = control
        .hello(with_token(hello(), &renewed))
        .await
        .unwrap_err();

    for status in [&none, &bad, &rotated, &revoked] {
        assert_eq!(
            refused(status),
            (Code::Unauthenticated, "TOKEN_REFUSED".to_owned())
        );
    }
    assert!(none.message().contains("current bearer token"), "{none:?}");
    assert!(after_renewal.is_ok());
}

#[tokio::test]
async fn a_token_still_works_beside_one_issued_to_the_same_client_after_it() {
    let server = start().await;
    let (client, old) = client_with_token(&server, "bench-1").await;

    let new = token_for(&server, &client.client_id, &client.client_secret).await;
    let connection = grpc(&server).await;
    let mut control = control(&connection);

    assert!(control.hello(with_token(hello(), &old)).await.is_ok());
    assert!(control.hello(with_token(hello(), &new)).await.is_ok());
    assert_ne!(old, new);
}

#[tokio::test]
async fn a_token_works_under_every_name_and_address_of_the_server() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;

    for host in ["localhost", "127.0.0.1", "some.other.name"] {
        let (stream, _) = tls(server.local_addr(), false).await;
        let connection = grpc_over(
            stream,
            format!("{host}:{}", server.local_addr().port()),
            None,
        )
        .await;

        let answer = control(&connection)
            .hello(with_token(hello(), &token))
            .await;

        assert!(answer.is_ok(), "{host}: {answer:?}");
    }
}

// ---- one port for HTTPS and gRPC ----

#[tokio::test]
async fn alpn_picks_h2_and_one_connection_carries_https_and_grpc() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let connection = grpc(&server).await;

    let info = {
        let mut connection = connection.clone();
        let request = http::Request::get("/skakel/info")
            .body(tonic::body::Body::empty())
            .unwrap();
        tower_service::Service::call(&mut connection, request)
            .await
            .unwrap()
    };
    let answer = control(&connection)
        .hello(with_token(hello(), &token))
        .await;

    assert_eq!(connection.alpn.as_deref(), Some(&b"h2"[..]));
    assert_eq!(info.status(), 200);
    assert_eq!(info.version(), http::Version::HTTP_2);
    assert!(answer.is_ok());
}

#[tokio::test]
async fn a_client_that_offers_only_http_1_1_gets_it_for_https() {
    let server = start().await;

    let (stream, _) = tls(server.local_addr(), true).await;

    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
    assert_eq!(Request::get("/skakel/info").send(&server).await.status, 200);
}

#[tokio::test]
async fn a_request_that_is_not_grpc_goes_to_https_and_an_unknown_service_is_unimplemented() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let connection = grpc(&server).await;

    let as_json = {
        let mut connection = connection.clone();
        let request = http::Request::post("/skakel.v2.ControlService/Hello")
            .header("content-type", "application/json")
            .body(tonic::body::Body::empty())
            .unwrap();
        tower_service::Service::call(&mut connection, request)
            .await
            .unwrap()
    };
    let unknown = {
        let mut grpc = tonic::client::Grpc::new(connection.clone());
        grpc.ready().await.unwrap();
        grpc.unary(
            with_token(hello(), &token),
            http::uri::PathAndQuery::from_static("/other.v1.Nothing/Here"),
            tonic_prost::ProstCodec::<HelloRequest, skakel_proto::v2::HelloResponse>::default(),
        )
        .await
        .unwrap_err()
    };

    assert_eq!(as_json.status(), 404);
    assert_eq!(unknown.code(), Code::Unimplemented);
}

/// `request` with its messages said to be compressed with `encoding`. They are not, so a server
/// that took the encoding would fail to read them, not refuse the call.
fn encoded<T>(mut request: tonic::Request<T>, encoding: &'static str) -> tonic::Request<T> {
    request
        .metadata_mut()
        .insert("grpc-encoding", encoding.parse().unwrap());
    request
}

#[tokio::test]
async fn a_compressed_call_is_unimplemented_and_identity_is_taken() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let connection = grpc(&server).await;

    let hello_gzip = control(&connection)
        .hello(encoded(with_token(hello(), &token), "gzip"))
        .await
        .unwrap_err();
    let (frames, rx) = tokio::sync::mpsc::channel::<OpenRequest>(1);
    let stream_zstd = streams(&connection)
        .open(encoded(with_token(ReceiverStream::new(rx), &token), "zstd"))
        .await
        .unwrap_err();
    drop(frames);
    let hello_identity = control(&connection)
        .hello(encoded(with_token(hello(), &token), "identity"))
        .await;

    assert_eq!(hello_gzip.code(), Code::Unimplemented);
    assert_eq!(stream_zstd.code(), Code::Unimplemented);
    assert!(hello_identity.is_ok(), "{hello_identity:?}");
}

#[tokio::test]
async fn every_connection_shows_the_certificate_because_no_session_is_resumed() {
    let server = start().await;
    // One client config for both connections, so the second would resume the first's session if
    // the server allowed it, and its handshake would show no certificate.
    let (config, verifier) = tls_config(&[b"h2"]);

    let first = tls_with(server.local_addr(), config.clone()).await;
    drop(first);
    *verifier.presented.lock().unwrap() = None;
    let _second = tls_with(server.local_addr(), config).await;

    assert!(verifier.presented.lock().unwrap().is_some());
}

// ---- the control channel ----

#[tokio::test]
async fn connect_starts_with_the_certificates() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let connection = grpc(&server).await;

    let mut call = connect(&connection, &token).await.unwrap();
    let first = call.next().await.unwrap();

    let Some(connect_response::Message::Certificates(certificates)) = first else {
        panic!("not certificates: {first:?}");
    };
    assert_eq!(certificates.fingerprint, server.fingerprint());
    assert_eq!(certificates.next_fingerprint, "");
}

#[tokio::test]
async fn connect_needs_a_current_token() {
    let server = start().await;
    let connection = grpc(&server).await;

    let none = control(&connection)
        .connect(ReceiverStream::new(tokio::sync::mpsc::channel(1).1))
        .await
        .unwrap_err();
    let bad = connect(&connection, "a.b.c").await.err().unwrap();

    assert_eq!(
        refused(&none),
        (Code::Unauthenticated, "TOKEN_REFUSED".to_owned())
    );
    assert_eq!(
        refused(&bad),
        (Code::Unauthenticated, "TOKEN_REFUSED".to_owned())
    );
}

#[tokio::test]
async fn a_client_may_hold_more_than_one_connect_call_on_one_connection() {
    let server = start().await;
    let (client, token) = client_with_token(&server, "bench-1").await;
    let connection = grpc(&server).await;

    let mut old = connect(&connection, &token).await.unwrap();
    old.next().await.unwrap();
    let renewed = token_for(&server, &client.client_id, &client.client_secret).await;
    let mut new = connect(&connection, &renewed).await.unwrap();
    new.next().await.unwrap();
    assert_eq!(server.open_sessions(&client.client_id), 2);
    drop(old);

    eventually("the old call ends", || {
        server.open_sessions(&client.client_id) == 1
    })
    .await;
}

#[tokio::test]
async fn a_revoked_client_is_told_why_its_call_ends_and_cannot_connect_again() {
    let server = start().await;
    let (client, token) = client_with_token(&server, "bench-1").await;
    let connection = grpc(&server).await;
    let mut call = connect(&connection, &token).await.unwrap();
    call.next().await.unwrap();
    assert_eq!(server.open_sessions(&client.client_id), 1);

    server.clients().revoke(&client.client_id).await.unwrap();

    let closing = call.next().await.unwrap();
    assert!(matches!(
        closing,
        Some(connect_response::Message::Closing(c)) if c.reason == ClosingReason::Revoked as i32
    ));
    let end = call.next().await.unwrap_err();
    assert_eq!(refused(&end), (Code::Unauthenticated, "REVOKED".to_owned()));
    let again = connect(&connection, &token).await.err().unwrap();
    assert_eq!(
        refused(&again),
        (Code::Unauthenticated, "TOKEN_REFUSED".to_owned())
    );
}

#[tokio::test]
async fn a_rotated_secret_ends_connect_with_rotated() {
    let server = start().await;
    let (client, token) = client_with_token(&server, "bench-1").await;
    let connection = grpc(&server).await;
    let mut call = connect(&connection, &token).await.unwrap();
    call.next().await.unwrap();

    server
        .clients()
        .rotate_secret(&client.client_id)
        .await
        .unwrap();

    assert!(matches!(
        call.next().await.unwrap(),
        Some(connect_response::Message::Closing(c)) if c.reason == ClosingReason::Rotated as i32
    ));
    let end = call.next().await.unwrap_err();
    assert_eq!(refused(&end), (Code::Unauthenticated, "ROTATED".to_owned()));
}

#[tokio::test]
async fn stopping_the_server_ends_control_calls_streams_and_app_calls_with_stopping() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let connection = grpc(&server).await;
    let mut call = connect(&connection, &token).await.unwrap();
    call.next().await.unwrap();
    let mut stream = open_stream(&server, &token, "echo", b"a").await.unwrap();
    let mut watch = greeter::watch(connection.clone(), with_token(WatchRequest {}, &token))
        .await
        .unwrap();
    watch.message().await.unwrap();

    let stopping = tokio::spawn(server.shutdown());

    assert!(matches!(
        call.next().await.unwrap(),
        Some(connect_response::Message::Closing(c)) if c.reason == ClosingReason::Stopping as i32
    ));
    let control_end = call.next().await.unwrap_err();
    let stream_end = stream.next().await.unwrap_err();
    let watch_end = watch.message().await.unwrap_err();
    for end in [&control_end, &stream_end, &watch_end] {
        assert_eq!(refused(end), (Code::Unavailable, "STOPPING".to_owned()));
    }
    stopping.await.unwrap();
}

#[tokio::test]
async fn connect_ends_with_token_expired_when_its_token_runs_out_and_app_calls_go_on() {
    let server = bench_builder()
        .token_lifetime(Duration::from_secs(2))
        .start()
        .await
        .unwrap();
    let (_, token) = client_with_token(&server, "bench-1").await;
    let connection = grpc(&server).await;
    let mut call = connect(&connection, &token).await.unwrap();
    call.next().await.unwrap();
    let mut watch = greeter::watch(connection.clone(), with_token(WatchRequest {}, &token))
        .await
        .unwrap();
    watch.message().await.unwrap();
    let mut stream = open_stream(&server, &token, "echo", b"a").await.unwrap();

    let end = call.next().await.unwrap_err();
    tokio::time::sleep(Duration::from_secs(1)).await;
    stream.send_data(&b"still here"[..]).await;

    assert_eq!(
        refused(&end),
        (Code::Unauthenticated, "TOKEN_EXPIRED".to_owned())
    );
    assert!(matches!(
        stream.next().await.unwrap(),
        Some(open_response::Frame::Data(d)) if d == "still here"
    ));
    let more = tokio::time::timeout(Duration::from_millis(300), watch.message()).await;
    assert!(more.is_err(), "the app call is still open: {more:?}");
}

#[tokio::test]
async fn a_control_call_hears_the_handover_and_its_acknowledgement_is_recorded() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let connection = grpc(&server).await;
    let mut call = connect(&connection, &token).await.unwrap();
    call.next().await.unwrap();

    let next = server
        .certificates()
        .prepare_next_certificate()
        .await
        .unwrap()
        .unwrap();

    let Some(connect_response::Message::Certificates(told)) = call.next().await.unwrap() else {
        panic!("no certificates");
    };
    assert_eq!(told.next_fingerprint, next);
    call.requests
        .send(ConnectRequest {
            message: Some(connect_request::Message::NextCertificateReceived(
                NextCertificateReceived {
                    fingerprint: next.clone(),
                },
            )),
        })
        .await
        .unwrap();
    eventually("the acknowledgement is recorded", || {
        server.clients().all()[0].has_next_certificate
    })
    .await;
    server.certificates().switch_certificate().await.unwrap();
    let Some(connect_response::Message::Certificates(switched)) = call.next().await.unwrap() else {
        panic!("no certificates after the switch");
    };
    assert_eq!(switched.fingerprint, next);
    assert_eq!(switched.next_fingerprint, "");
}

#[tokio::test]
async fn an_acknowledgement_of_the_wrong_certificate_is_not_recorded() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let connection = grpc(&server).await;
    let mut call = connect(&connection, &token).await.unwrap();
    call.next().await.unwrap();
    server
        .certificates()
        .prepare_next_certificate()
        .await
        .unwrap();
    call.next().await.unwrap();

    call.requests
        .send(ConnectRequest {
            message: Some(connect_request::Message::NextCertificateReceived(
                NextCertificateReceived {
                    fingerprint: "AA:BB".into(),
                },
            )),
        })
        .await
        .unwrap();
    // A message of a kind the server does not know is ignored too.
    call.requests
        .send(ConnectRequest { message: None })
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert!(!server.clients().all()[0].has_next_certificate);
    let still_open = tokio::time::timeout(Duration::from_millis(200), call.answers.message()).await;
    assert!(still_open.is_err(), "the call is still open");
}

#[tokio::test]
async fn a_cancelled_handover_is_told_with_an_empty_next_fingerprint() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let connection = grpc(&server).await;
    let mut call = connect(&connection, &token).await.unwrap();
    call.next().await.unwrap();
    server
        .certificates()
        .prepare_next_certificate()
        .await
        .unwrap();
    call.next().await.unwrap();

    server
        .certificates()
        .cancel_next_certificate()
        .await
        .unwrap();

    let Some(connect_response::Message::Certificates(cancelled)) = call.next().await.unwrap()
    else {
        panic!("no certificates");
    };
    assert_eq!(cancelled.next_fingerprint, "");
    assert!(fingerprints::are_equal(
        &cancelled.fingerprint,
        &server.fingerprint()
    ));
}

#[tokio::test]
async fn a_control_message_over_one_mib_ends_the_call_with_resource_exhausted() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let connection = grpc(&server).await;
    let mut call = connect(&connection, &token).await.unwrap();
    call.next().await.unwrap();

    call.requests
        .send(ConnectRequest {
            message: Some(connect_request::Message::NextCertificateReceived(
                NextCertificateReceived {
                    fingerprint: "A".repeat(1024 * 1024 + 1),
                },
            )),
        })
        .await
        .unwrap();

    let end = call.next().await.unwrap_err();
    assert_eq!(end.code(), Code::ResourceExhausted);
}

// ---- keep-alive ----

/// A TLS stream that notes when the server sends an HTTP/2 PING, and that can be frozen so the
/// client reads and writes nothing more, as one that hangs.
struct Watched<S> {
    inner: S,
    parser: Mutex<FrameParser>,
    pings: Arc<Mutex<Vec<Instant>>>,
    frozen: Arc<AtomicBool>,
}

#[derive(Default)]
struct FrameParser {
    header: Vec<u8>,
    payload_left: usize,
}

impl FrameParser {
    /// Reads frames from what the server sent; `ping` is called for each PING that is not an ACK.
    fn feed(&mut self, mut bytes: &[u8], mut ping: impl FnMut()) {
        while !bytes.is_empty() {
            if self.payload_left > 0 {
                let take = self.payload_left.min(bytes.len());
                self.payload_left -= take;
                bytes = &bytes[take..];
                continue;
            }
            let take = (9 - self.header.len()).min(bytes.len());
            self.header.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.header.len() == 9 {
                let length = (usize::from(self.header[0]) << 16)
                    | (usize::from(self.header[1]) << 8)
                    | usize::from(self.header[2]);
                if self.header[3] == 0x6 && self.header[4] & 0x1 == 0 {
                    ping();
                }
                self.payload_left = length;
                self.header.clear();
            }
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Watched<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.frozen.load(Ordering::Relaxed) {
            return Poll::Pending;
        }
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        let read = buf.filled()[before..].to_vec();
        let pings = self.pings.clone();
        self.parser
            .lock()
            .unwrap()
            .feed(&read, || pings.lock().unwrap().push(Instant::now()));
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Watched<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.frozen.load(Ordering::Relaxed) {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.frozen.load(Ordering::Relaxed) {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A gRPC connection whose PINGs from the server are noted, and which can be frozen.
async fn watched_connection(
    server: &skakel_server::SkakelServer,
) -> (Grpc, Arc<Mutex<Vec<Instant>>>, Arc<AtomicBool>) {
    let (stream, _) = tls(server.local_addr(), false).await;
    let pings = Arc::new(Mutex::new(vec![]));
    let frozen = Arc::new(AtomicBool::new(false));
    let watched = Watched {
        inner: stream,
        parser: Mutex::new(FrameParser::default()),
        pings: pings.clone(),
        frozen: frozen.clone(),
    };
    let connection = grpc_over(
        watched,
        format!("localhost:{}", server.local_addr().port()),
        None,
    )
    .await;
    (connection, pings, frozen)
}

#[tokio::test]
async fn the_server_pings_a_connection_that_carries_grpc_after_15_quiet_seconds() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let (connection, pings, _) = watched_connection(&server).await;
    let mut call = connect(&connection, &token).await.unwrap();
    call.next().await.unwrap();
    let quiet_since = Instant::now();

    tokio::time::sleep(Duration::from_secs(19)).await;

    let after: Vec<Duration> = pings
        .lock()
        .unwrap()
        .iter()
        .filter(|at| **at > quiet_since)
        .map(|at| at.duration_since(quiet_since))
        .collect();
    assert!(
        after
            .iter()
            .any(|d| *d >= Duration::from_secs(13) && *d <= Duration::from_secs(18)),
        "pings after the call started: {after:?}"
    );
}

#[tokio::test]
async fn the_server_drops_a_connection_that_has_said_nothing_for_30_seconds() {
    let server = start().await;
    let (client, token) = client_with_token(&server, "bench-1").await;
    let (connection, _, frozen) = watched_connection(&server).await;
    let mut call = connect(&connection, &token).await.unwrap();
    call.next().await.unwrap();
    assert_eq!(server.open_sessions(&client.client_id), 1);

    frozen.store(true, Ordering::Relaxed);
    let since = Instant::now();
    while server.open_sessions(&client.client_id) > 0 {
        assert!(
            since.elapsed() < Duration::from_secs(40),
            "the connection is still up"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    let after = since.elapsed();
    assert!(after >= Duration::from_secs(25), "dropped after {after:?}");
}

// ---- streams ----

#[tokio::test]
async fn a_stream_is_refused_before_opened_with_the_reason_and_words_a_person_can_read() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let connection = grpc(&server).await;
    let open = |token: &'static str, stream_type: &'static str, target: &'static [u8]| {
        let connection = connection.clone();
        async move {
            open_stream_on(&connection, token, stream_type, target)
                .await
                .err()
                .expect("refused")
        }
    };
    let token: &'static str = Box::leak(token.into_boxed_str());

    let no_token = open("", "echo", b"a").await;
    let bad_token = open("a.b.c", "echo", b"a").await;
    let unknown = open(token, "nope", b"a").await;
    let bad_type = open(token, "No/Pe", b"a").await;
    let bad_target = open(token, "echo", b"").await;
    let missing = open(token, "echo", b"missing").await;
    let busy = open(token, "echo", b"busy").await;

    assert_eq!(
        refused(&no_token),
        (Code::Unauthenticated, "TOKEN_REFUSED".to_owned())
    );
    assert_eq!(
        refused(&bad_token),
        (Code::Unauthenticated, "TOKEN_REFUSED".to_owned())
    );
    assert_eq!(
        (refused(&unknown), unknown.message()),
        (
            (Code::NotFound, "NO_SUCH_TYPE".to_owned()),
            "This server has no stream type 'nope'."
        )
    );
    assert_eq!(
        refused(&bad_type),
        (Code::InvalidArgument, "BAD_OPEN".to_owned())
    );
    assert_eq!(
        (refused(&bad_target), bad_target.message()),
        (
            (Code::InvalidArgument, "BAD_TARGET".to_owned()),
            "Say which target."
        )
    );
    assert_eq!(
        (refused(&missing), missing.message()),
        (
            (Code::NotFound, "NO_SUCH_TARGET".to_owned()),
            "There is no target called missing."
        )
    );
    assert_eq!(
        (refused(&busy), busy.message()),
        (
            (Code::FailedPrecondition, "IN_USE".to_owned()),
            "bench-2 holds busy."
        )
    );
}

#[tokio::test]
async fn a_stream_whose_first_frame_is_not_open_is_bad_open() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let connection = grpc(&server).await;
    let (frames, rx) = tokio::sync::mpsc::channel(4);
    frames
        .send(OpenRequest {
            frame: Some(open_request::Frame::Data(Bytes::from_static(b"hi"))),
        })
        .await
        .unwrap();

    let refusal = streams(&connection)
        .open(with_token(ReceiverStream::new(rx), &token))
        .await
        .unwrap_err();

    assert_eq!(
        refused(&refusal),
        (Code::InvalidArgument, "BAD_OPEN".to_owned())
    );
}

#[tokio::test]
async fn a_stream_with_no_open_within_15_seconds_is_bad_open() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let connection = grpc(&server).await;
    let (_frames, rx) = tokio::sync::mpsc::channel::<OpenRequest>(4);
    let started = Instant::now();

    let refusal = streams(&connection)
        .open(with_token(ReceiverStream::new(rx), &token))
        .await
        .unwrap_err();

    assert_eq!(
        refused(&refusal),
        (Code::InvalidArgument, "BAD_OPEN".to_owned())
    );
    assert!(started.elapsed() >= Duration::from_secs(14));
}

#[tokio::test]
async fn a_frame_sent_before_opened_is_bad_frame() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let connection = grpc(&server).await;
    let (frames, rx) = tokio::sync::mpsc::channel(4);
    for frame in [
        open_request::Frame::Open(skakel_proto::v2::StreamOpen {
            stream_type: "echo".into(),
            target: Bytes::from_static(b"late"),
        }),
        open_request::Frame::Data(Bytes::from_static(b"too soon")),
    ] {
        frames
            .send(OpenRequest { frame: Some(frame) })
            .await
            .unwrap();
    }

    let refusal = streams(&connection)
        .open(with_token(ReceiverStream::new(rx), &token))
        .await
        .unwrap_err();

    assert_eq!(
        refused(&refusal),
        (Code::InvalidArgument, "BAD_FRAME".to_owned())
    );
}

#[tokio::test]
async fn a_second_open_or_an_empty_frame_after_opened_ends_the_stream_with_bad_frame() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let mut again = open_stream(&server, &token, "echo", b"a").await.unwrap();
    let mut empty = open_stream(&server, &token, "echo", b"a").await.unwrap();

    again
        .frames
        .send(OpenRequest {
            frame: Some(open_request::Frame::Open(skakel_proto::v2::StreamOpen {
                stream_type: "echo".into(),
                target: Bytes::new(),
            })),
        })
        .await
        .unwrap();
    empty
        .frames
        .send(OpenRequest { frame: None })
        .await
        .unwrap();

    for stream in [&mut again, &mut empty] {
        let end = stream.next().await.unwrap_err();
        assert_eq!(
            refused(&end),
            (Code::InvalidArgument, "BAD_FRAME".to_owned())
        );
    }
}

#[tokio::test]
async fn a_stream_carries_data_and_control_frames_in_order_and_closes_with_ok() {
    let server = start().await;
    let (client, token) = client_with_token(&server, "bench-1").await;
    let mut stream = open_stream(&server, &token, "echo", b"a b").await.unwrap();
    assert_eq!(server.open_sessions(&client.client_id), 1);

    stream.send_data(&b"ping"[..]).await;
    stream.send_control(&b"\x08\x01"[..]).await;
    stream.send_data(&b"pong"[..]).await;

    assert_eq!(
        stream.next().await.unwrap(),
        Some(open_response::Frame::Data(Bytes::from_static(b"ping")))
    );
    assert_eq!(
        stream.next().await.unwrap(),
        Some(open_response::Frame::Control(Bytes::from_static(
            b"\x08\x01"
        )))
    );
    assert_eq!(
        stream.next().await.unwrap(),
        Some(open_response::Frame::Data(Bytes::from_static(b"pong")))
    );
    // The client ends its side: the server sends what it still has, then OK.
    stream.send_data(&b"last"[..]).await;
    drop(stream.frames);
    assert_eq!(
        stream
            .answers
            .message()
            .await
            .unwrap()
            .and_then(|a| a.frame),
        Some(open_response::Frame::Data(Bytes::from_static(b"last")))
    );
    assert_eq!(stream.answers.message().await.unwrap(), None);
    eventually("the stream is let go", || {
        server.open_sessions(&client.client_id) == 0
    })
    .await;
}

#[tokio::test]
async fn a_large_amount_of_data_comes_back_whole_past_a_handler_that_is_slow_to_read() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let stream = open_stream(&server, &token, "echo", b"slow").await.unwrap();
    let chunk: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    let TestStream {
        frames,
        mut answers,
    } = stream;
    let sender = tokio::spawn({
        let chunk = chunk.clone();
        async move {
            for _ in 0..100 {
                frames
                    .send(OpenRequest {
                        frame: Some(open_request::Frame::Data(chunk.clone().into())),
                    })
                    .await
                    .unwrap();
            }
            frames
        }
    });

    let mut received = 0usize;
    while received < chunk.len() * 100 {
        let frame = tokio::time::timeout(Duration::from_secs(20), answers.message())
            .await
            .unwrap()
            .unwrap()
            .and_then(|a| a.frame);
        let Some(open_response::Frame::Data(data)) = frame else {
            panic!("the stream ended early after {received} bytes");
        };
        assert_eq!(&data[..], &chunk[..], "a frame arrives whole and in order");
        received += data.len();
    }
    let _frames = sender.await.unwrap();
}

#[tokio::test]
async fn a_target_that_goes_away_ends_with_target_gone() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let mut stream = open_stream(&server, &token, "echo", b"vanish")
        .await
        .unwrap();

    let end = stream.next().await.unwrap_err();

    assert_eq!(
        (refused(&end), end.message()),
        ((Code::NotFound, "TARGET_GONE".to_owned()), "unplugged")
    );
}

#[tokio::test]
async fn a_stream_type_ends_a_stream_with_aborted_in_a_domain_of_its_own() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let mut stream = open_stream(&server, &token, "echo", b"abort")
        .await
        .unwrap();

    let end = stream.next().await.unwrap_err();

    assert_eq!(end.code(), Code::Aborted);
    assert_eq!(
        reason_of(&end),
        Some(("skakel.streams.echo".to_owned(), "WORN_OUT".to_owned()))
    );
}

#[tokio::test]
async fn revoking_and_rotating_end_streams_with_revoked_and_rotated() {
    let server = start().await;
    let (revoked, token) = client_with_token(&server, "bench-1").await;
    let (rotated, token2) = client_with_token(&server, "bench-2").await;
    let mut a = open_stream(&server, &token, "echo", b"a").await.unwrap();
    let mut b = open_stream(&server, &token2, "echo", b"a").await.unwrap();

    server.clients().revoke(&revoked.client_id).await.unwrap();
    server
        .clients()
        .rotate_secret(&rotated.client_id)
        .await
        .unwrap();

    let a_end = a.next().await.unwrap_err();
    let b_end = b.next().await.unwrap_err();
    assert_eq!(
        refused(&a_end),
        (Code::Unauthenticated, "REVOKED".to_owned())
    );
    assert_eq!(
        refused(&b_end),
        (Code::Unauthenticated, "ROTATED".to_owned())
    );
}

#[tokio::test]
async fn streams_run_on_a_shared_connection_as_well_as_on_their_own() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let shared = grpc(&server).await;
    let mut call = connect(&shared, &token).await.unwrap();
    call.next().await.unwrap();
    let mut first = open_stream_on(&shared, &token, "echo", b"a").await.unwrap();
    let mut second = open_stream_on(&shared, &token, "echo", b"b").await.unwrap();
    let mut own = open_stream(&server, &token, "echo", b"c").await.unwrap();

    for (stream, text) in [
        (&mut first, "one"),
        (&mut second, "two"),
        (&mut own, "three"),
    ] {
        stream.send_data(text.as_bytes().to_vec()).await;
        assert!(matches!(
            stream.next().await.unwrap(),
            Some(open_response::Frame::Data(d)) if d == text.as_bytes()
        ));
    }
}

#[tokio::test]
async fn a_frame_over_16_mib_ends_the_stream_with_resource_exhausted() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let mut stream = open_stream(&server, &token, "echo", b"a").await.unwrap();

    stream.send_data(vec![7u8; 16 * 1024 * 1024 + 1]).await;

    let end = stream
        .next_within(Duration::from_secs(30))
        .await
        .unwrap_err();
    assert_eq!(end.code(), Code::ResourceExhausted);
}

#[tokio::test]
async fn a_frame_over_16_mib_from_the_server_ends_the_stream_with_resource_exhausted() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let mut stream = open_stream(&server, &token, "echo", b"huge").await.unwrap();

    let end = stream
        .next_within(Duration::from_secs(30))
        .await
        .unwrap_err();
    assert_eq!(end.code(), Code::ResourceExhausted);
}

#[tokio::test]
async fn the_serial_stream_type_speaks_the_messages_of_serial_proto() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let mut stream = open_stream(&server, &token, "serial", &serial_target("COM1"))
        .await
        .unwrap();
    let control = |frame: Option<open_response::Frame>| match frame {
        Some(open_response::Frame::Control(bytes)) => {
            SerialServerMessage::decode(bytes).unwrap().message.unwrap()
        }
        other => panic!("not control: {other:?}"),
    };

    let opened = control(stream.next().await.unwrap());
    assert!(matches!(opened, serial_server_message::Message::Opened(_)));
    stream
        .send_control(
            SerialClientMessage {
                message: Some(serial_client_message::Message::ModemLines(
                    skakel_proto::v2::ModemLines {
                        dtr: Some(true),
                        rts: None,
                    },
                )),
            }
            .encode_to_vec(),
        )
        .await;
    let status = control(stream.next().await.unwrap());
    assert!(matches!(status, serial_server_message::Message::ModemStatus(s) if s.dsr && s.dcd));

    let busy = open_stream(&server, &token, "serial", &serial_target("busy"))
        .await
        .err()
        .unwrap();
    assert_eq!(
        refused(&busy),
        (Code::FailedPrecondition, "IN_USE".to_owned())
    );
    let mut fault = open_stream(&server, &token, "serial", &serial_target("fault"))
        .await
        .unwrap();
    fault.next().await.unwrap();
    let end = fault.next().await.unwrap_err();
    assert_eq!(
        (end.code(), reason_of(&end)),
        (
            Code::Aborted,
            Some(("skakel.streams.serial".to_owned(), "PORT_FAULT".to_owned()))
        )
    );
}

/// Not a check: how fast one stream carries bulk bytes from a client to the server over loopback.
/// Run with `cargo test --release -p skakel-server --test grpc -- --ignored --nocapture`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "a measurement, not a check"]
async fn throughput_of_one_stream_over_loopback() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let mut stream = open_stream(&server, &token, "echo", b"sink").await.unwrap();
    let chunk = Bytes::from(vec![0x5Au8; 64 * 1024]);
    let total: u64 = 1024 * 1024 * 1024;

    let started = Instant::now();
    let frames = stream.frames.clone();
    let sender = tokio::spawn(async move {
        for _ in 0..total / chunk.len() as u64 {
            frames
                .send(OpenRequest {
                    frame: Some(open_request::Frame::Data(chunk.clone())),
                })
                .await
                .unwrap();
        }
    });
    sender.await.unwrap();
    drop(stream.frames);
    let counted = match stream
        .answers
        .message()
        .await
        .unwrap()
        .and_then(|a| a.frame)
    {
        Some(open_response::Frame::Control(bytes)) => {
            u64::from_be_bytes(bytes[..8].try_into().unwrap())
        }
        other => panic!("no count: {other:?}"),
    };
    let seconds = started.elapsed().as_secs_f64();

    assert_eq!(counted, total);
    eprintln!(
        "one stream, {} MiB in 64 KiB frames: {:.2} s, {:.0} MiB/s",
        total >> 20,
        seconds,
        (total >> 20) as f64 / seconds
    );
}

// ---- the app's own services ----

#[tokio::test]
async fn an_apps_service_runs_beside_skakels_on_the_same_connection_and_knows_who_called() {
    let server = start().await;
    let (client, token) = client_with_token(&server, "bench-1").await;
    let connection = grpc(&server).await;
    let mut call = connect(&connection, &token).await.unwrap();
    call.next().await.unwrap();

    let reply = greeter::greet(
        connection.clone(),
        with_token(GreetRequest { text: "hi".into() }, &token),
    )
    .await
    .unwrap();

    assert_eq!(reply.text, format!("{}: hi", client.client_id));
}

#[tokio::test]
async fn an_apps_service_never_sees_a_call_without_a_current_token() {
    let server = start().await;
    let (client, token) = client_with_token(&server, "bench-1").await;
    let connection = grpc(&server).await;

    let none = greeter::greet(
        connection.clone(),
        tonic::Request::new(GreetRequest { text: "hi".into() }),
    )
    .await
    .unwrap_err();
    server.clients().revoke(&client.client_id).await.unwrap();
    let revoked = greeter::greet(
        connection.clone(),
        with_token(GreetRequest { text: "hi".into() }, &token),
    )
    .await
    .unwrap_err();

    for status in [&none, &revoked] {
        assert_eq!(
            refused(status),
            (Code::Unauthenticated, "TOKEN_REFUSED".to_owned())
        );
    }
}

#[tokio::test]
async fn revoking_or_rotating_a_client_ends_its_running_app_calls() {
    let server = start().await;
    let (revoked, token) = client_with_token(&server, "bench-1").await;
    let (rotated, token2) = client_with_token(&server, "bench-2").await;
    let connection = grpc(&server).await;
    let mut a = greeter::watch(connection.clone(), with_token(WatchRequest {}, &token))
        .await
        .unwrap();
    let mut b = greeter::watch(connection.clone(), with_token(WatchRequest {}, &token2))
        .await
        .unwrap();
    let first = a.message().await.unwrap().unwrap();
    b.message().await.unwrap();
    assert_eq!(first.text, format!("watching for {}", revoked.client_id));
    assert_eq!(server.open_sessions(&revoked.client_id), 1);

    server.clients().revoke(&revoked.client_id).await.unwrap();
    server
        .clients()
        .rotate_secret(&rotated.client_id)
        .await
        .unwrap();

    let a_end = a.message().await.unwrap_err();
    let b_end = b.message().await.unwrap_err();
    assert_eq!(
        refused(&a_end),
        (Code::Unauthenticated, "REVOKED".to_owned())
    );
    assert_eq!(
        refused(&b_end),
        (Code::Unauthenticated, "ROTATED".to_owned())
    );
    eventually("the app calls are let go", || {
        server.open_sessions(&revoked.client_id) == 0
    })
    .await;
}
