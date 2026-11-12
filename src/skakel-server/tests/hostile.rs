//! What a hostile or broken peer can and cannot do to the server: garbage and oversized gRPC
//! frames, a gRPC call over HTTP/1.1, a flood of discovery datagrams, source addresses rotated
//! inside one IPv6 `/64` or spread over many, and stream handlers that panic or never end.

mod common;

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use axum::extract::ConnectInfo;
use common::*;
use http_body_util::{BodyExt, Full};
use prost::bytes::Bytes;
use serde_json::json;
use skakel_discovery::{PROBE_SIZE, create_probe};
use skakel_pairing::{commit, new_nonce};
use skakel_proto::v2::HelloRequest;
use skakel_server::StreamOpen as Opening;
use tokio::net::UdpSocket;
use tonic::Code;
use tonic::body::Body;
use tonic::codegen::http;
use tower_service::Service;

/// A gRPC call to `Hello` with `body` as its whole request body, and the status it ends with.
async fn raw_hello(connection: &mut Grpc, token: &str, body: Vec<u8>) -> (u16, Option<String>) {
    let request = http::Request::post("/skakel.v2.ControlService/Hello")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::new(Full::new(Bytes::from(body))))
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(10), connection.call(request))
        .await
        .expect("an answer, not a hang")
        .expect("the connection stays up");
    let status = response.status().as_u16();
    let mut grpc_status = response
        .headers()
        .get("grpc-status")
        .map(|v| v.to_str().unwrap().to_owned());
    let collected = response.into_body().collect().await.expect("the body ends");
    if grpc_status.is_none() {
        grpc_status = collected
            .trailers()
            .and_then(|t| t.get("grpc-status"))
            .map(|v| v.to_str().unwrap().to_owned());
    }
    (status, grpc_status)
}

fn framed(message: &[u8]) -> Vec<u8> {
    let mut frame = vec![0u8];
    frame.extend_from_slice(&(message.len() as u32).to_be_bytes());
    frame.extend_from_slice(message);
    frame
}

#[tokio::test]
async fn garbage_in_a_grpc_frame_is_an_error_status_and_the_connection_goes_on() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let mut connection = grpc(&server).await;

    // A frame whose message is not protobuf, one with a bad compression flag, one cut short, and
    // one with no body at all.
    let not_protobuf = framed(&[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
    ]);
    let mut bad_flag = framed(&[]);
    bad_flag[0] = 7;
    let mut cut_short = framed(&[1, 2, 3, 4]);
    cut_short.truncate(7);
    for body in [not_protobuf, bad_flag, cut_short, vec![0, 1]] {
        let (_, status) = raw_hello(&mut connection, &token, body).await;
        assert_ne!(status.as_deref(), Some("0"), "garbage is never a success");
    }

    // The same connection and the server go on working.
    let hello = control(&connection)
        .hello(with_token(HelloRequest {}, &token))
        .await
        .expect("a good call after the garbage")
        .into_inner();
    assert_eq!(hello.server, NAME);
}

#[tokio::test]
async fn a_frame_that_claims_four_gib_is_refused_without_being_waited_for() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let mut connection = grpc(&server).await;

    // A length prefix of u32::MAX and only a few bytes after it.
    let mut claim = vec![0u8];
    claim.extend_from_slice(&u32::MAX.to_be_bytes());
    claim.extend_from_slice(&[1, 2, 3]);
    let (_, status) = raw_hello(&mut connection, &token, claim).await;

    assert_eq!(
        status.as_deref(),
        Some("8"),
        "RESOURCE_EXHAUSTED, from the length alone"
    );
}

#[tokio::test]
async fn a_grpc_call_over_http_1_1_is_not_served_as_grpc() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;

    let reply = Request::new("POST", "/skakel.v2.ControlService/Hello")
        .header("Content-Type", "application/grpc")
        .header("TE", "trailers")
        .bearer(&token)
        .send(&server)
        .await;

    // gRPC runs only over HTTP/2. Over HTTP/1.1 the call is not answered with a gRPC success.
    assert!(
        reply.status != 200 || reply.header("grpc-status").is_some_and(|s| s != "0"),
        "answered {} with {:?}",
        reply.status,
        reply.headers
    );
    assert!(!reply.text().contains(NAME), "no hello over HTTP/1.1");
}

#[tokio::test]
async fn a_flood_of_probes_and_junk_does_not_stop_the_server_answering_or_amplify() {
    let server = start().await;
    let target = server.discovery_addr().expect("discovery is on");
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Short junk is never answered; a full probe is, with no more bytes than it had.
    for n in 0..300u32 {
        let junk = vec![(n % 251) as u8; (n % 600) as usize];
        socket.send_to(&junk, target).await.unwrap();
    }
    for _ in 0..300 {
        socket.send_to(&create_probe(), target).await.unwrap();
    }
    let mut buffer = vec![0u8; 4096];
    let mut answers = 0;
    while let Ok(Ok((len, _))) =
        tokio::time::timeout(Duration::from_millis(500), socket.recv_from(&mut buffer)).await
    {
        assert!(len <= PROBE_SIZE, "an answer of {len} bytes");
        answers += 1;
    }
    assert!(answers > 0, "a flood does not silence the server");

    // After the flood a single probe is still answered.
    let fresh = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    fresh.send_to(&create_probe(), target).await.unwrap();
    let (len, _) = tokio::time::timeout(Duration::from_secs(3), fresh.recv_from(&mut buffer))
        .await
        .expect("an answer after the flood")
        .unwrap();
    assert!(len <= PROBE_SIZE);
}

/// A mounted server with no app listener, called through its service with a made-up caller.
async fn mounted() -> skakel_server::SkakelServer {
    bench_builder()
        .discovery(false)
        .start_mounted("127.0.0.1:5240".parse().unwrap())
        .await
        .unwrap()
}

async fn open_from(server: &skakel_server::SkakelServer, from: IpAddr) -> (u16, serde_json::Value) {
    let body = json!({ "clientName": "lab pc", "commitment": commit(&new_nonce().unwrap()) });
    let mut request = http::Request::post("/skakel/v2/pair")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(from, 50_000)));
    let response = server.service().call(request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or_default())
}

fn in_64(prefix: u16, host: u64) -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(
        (u128::from(0x2001_0db8_0000_0000u64 | u64::from(prefix)) << 64) | u128::from(host),
    ))
}

#[tokio::test]
async fn rotating_the_low_bits_of_one_ipv6_64_opens_no_more_requests_than_one_address() {
    let server = mounted().await;

    let mut opened = 0;
    for host in 1..=40u64 {
        if open_from(&server, in_64(1, host)).await.0 == 200 {
            opened += 1;
        }
    }

    assert_eq!(
        opened, 3,
        "one /64 is one address: three open at once is the most"
    );
}

#[tokio::test]
async fn many_64s_cannot_fill_the_servers_unrevealed_requests_past_its_cap() {
    let server = mounted().await;

    let mut opened = 0;
    for prefix in 1..=100u16 {
        if open_from(&server, in_64(prefix, 1)).await.0 == 200 {
            opened += 1;
        }
    }

    assert_eq!(
        opened, 64,
        "the server holds at most 64 unrevealed requests"
    );
    // An address that was refused for the cap is told to wait, and the server still answers.
    let (status, _) = open_from(&server, in_64(500, 1)).await;
    assert_eq!(status, 429);
}

/// A stream type whose handler panics once it is opened.
fn panicking() -> impl skakel_server::StreamHandler {
    |_| async {
        Opening::accept(|_session| async move {
            panic!("the handler is broken");
        })
    }
}

/// A stream type whose handler never reads and never ends.
fn hanging() -> impl skakel_server::StreamHandler {
    |_| async {
        Opening::accept(|session| async move {
            let _keep = &session;
            std::future::pending::<()>().await;
        })
    }
}

#[tokio::test]
async fn a_panicking_stream_handler_ends_its_stream_and_nothing_else() {
    let server = bench_builder()
        .stream("boom", panicking())
        .start()
        .await
        .unwrap();
    let (_, token) = client_with_token(&server, "bench-1").await;
    let connection = grpc(&server).await;
    let mut call = connect(&connection, &token).await.unwrap();
    call.next().await.unwrap();

    let mut boom = open_stream(&server, &token, "boom", b"").await.unwrap();
    let ended = boom.next().await;

    // The stream is over, with a status and not a hang.
    assert!(
        matches!(ended, Err(_) | Ok(None)),
        "the stream ends: {ended:?}"
    );
    // The control call, other streams and new calls are unaffected.
    let mut echo = open_stream(&server, &token, "echo", b"a").await.unwrap();
    echo.send_data(&b"still here"[..]).await;
    assert!(echo.next().await.is_ok());
    let hello = control(&connection)
        .hello(with_token(HelloRequest {}, &token))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(hello.server, NAME);
}

#[tokio::test]
async fn a_hanging_stream_handler_does_not_stop_shutdown_or_revoking() {
    let server = bench_builder()
        .stream("hang", hanging())
        .start()
        .await
        .unwrap();
    let (client, token) = client_with_token(&server, "bench-1").await;
    let mut stuck = open_stream(&server, &token, "hang", b"").await.unwrap();

    // Revoking the client ends its stream though the handler never returns.
    server.clients().revoke(&client.client_id).await.unwrap();
    let end = stuck.next().await.unwrap_err();
    assert_eq!(refused(&end).0, Code::Unauthenticated);

    // Shutdown with another hung stream still finishes in a bounded time.
    let (_, token) = client_with_token(&server, "bench-2").await;
    let mut other = open_stream(&server, &token, "hang", b"").await.unwrap();
    tokio::time::timeout(Duration::from_secs(8), server.shutdown())
        .await
        .expect("shutdown finishes though a handler never does");
    let end = other.next().await.unwrap_err();
    assert_eq!(refused(&end), (Code::Unavailable, "STOPPING".to_owned()));
}

#[tokio::test]
async fn a_body_that_stops_arriving_is_answered_and_given_up_on() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // This one waits on the server's own body timeout, so it takes as long as that does.
    let server = start().await;
    let (mut stream, _) = tls(server.local_addr(), true).await;
    stream
        .write_all(
            b"POST /skakel/v2/token HTTP/1.1\r\nHost: localhost\r\n\
              Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 64\r\n\r\n\
              grant_type=",
        )
        .await
        .unwrap();

    let mut buffer = vec![0u8; 1024];
    let read = tokio::time::timeout(Duration::from_secs(20), stream.read(&mut buffer)).await;

    let n = read
        .expect("the server answers or closes a stalled body within 20 seconds")
        .unwrap_or(0);
    let text = String::from_utf8_lossy(&buffer[..n]).to_string();
    assert!(
        n == 0 || text.starts_with("HTTP/1.1 400"),
        "a stalled body is a 400 or a closed connection: {text}"
    );
}
