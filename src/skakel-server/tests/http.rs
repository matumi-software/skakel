//! The server over TLS on loopback, as a client sees it over HTTPS: info, pairing, tokens, the
//! limits, the app's own routes, discovery, the certificate it presents and the state it keeps. The
//! gRPC side is in `grpc.rs`, and the Rust client's side in `skakel-client`'s own tests.

mod common;

use std::time::Duration;

use base64::Engine;
use common::*;
use serde_json::{Value, json};
use skakel_server::{Approval, ClientPrincipal, InMemoryStore, ServerEvent, SkakelServerBuilder};
use skakel_wire::fingerprints;
use skakel_wire::pairing::{commit, compute, new_nonce};
use tokio::net::UdpSocket;

// ---- info and discovery ----

#[tokio::test]
async fn info_is_served_without_a_token_in_the_shape_the_protocol_shows() {
    let server = start().await;

    let reply = Request::get("/skakel/info").send(&server).await;

    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.text(),
        r#"{"name":"rust-bench","app":{"id":"test-app","version":"1.2.3"},"versions":[2]}"#
    );
}

#[tokio::test]
async fn a_server_with_bad_options_does_not_start_and_says_what_is_wrong() {
    let error = match SkakelServerBuilder::new("Bad App", " ", InMemoryStore::new())
        .token_requests_per_minute(0)
        .grpc_service(greeter::Impostor)
        .grpc_service(greeter::Greeter)
        .grpc_service(greeter::Greeter)
        .stream("Echo", echo_stream())
        .start()
        .await
    {
        Ok(_) => panic!("started"),
        Err(error) => error.to_string(),
    };

    assert!(error.contains("app id"), "{error}");
    assert!(error.contains("app version"), "{error}");
    assert!(error.contains("rate limits"), "{error}");
    assert!(error.contains("'skakel.v2.Impostor'"), "{error}");
    assert!(error.contains("added twice"), "{error}");
    assert!(error.contains("stream type"), "{error}");
}

#[tokio::test]
async fn a_plain_http_request_to_the_port_is_told_to_use_https() {
    let server = start().await;

    let reply = Request::new("POST", "/skakel/v2/pair")
        .json(&json!({ "clientName": "a", "commitment": "A".repeat(64) }))
        .send_plain(&server)
        .await;

    assert_eq!(reply.status, 400);
    assert!(reply.detail().contains("HTTPS"));
}

#[tokio::test]
async fn discovery_answers_a_probe_with_the_servers_fingerprint_and_port_and_nothing_else() {
    let server = start().await;
    let address = server.discovery_addr().expect("discovery is on");
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    socket
        .send_to(&skakel_wire::discovery::create_probe(), address)
        .await
        .unwrap();
    let mut buffer = [0u8; 2048];
    let (length, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buffer))
        .await
        .expect("an answer")
        .unwrap();
    let answer =
        skakel_wire::discovery::try_parse_answer(&buffer[..length]).expect("a valid answer");

    assert_eq!(answer.name, "rust-bench");
    assert_eq!(answer.port, server.local_addr().port());
    assert_eq!(answer.app.id, "test-app");
    assert_eq!(answer.versions, [2]);
    assert!(fingerprints::are_equal(
        &answer.fingerprint,
        &server.fingerprint()
    ));

    // Short datagrams and other text get no answer.
    socket.send_to(&[0u8; 100], address).await.unwrap();
    socket.send_to(&vec![b'x'; 600], address).await.unwrap();
    let silent =
        tokio::time::timeout(Duration::from_millis(500), socket.recv_from(&mut buffer)).await;
    assert!(silent.is_err(), "nothing answers a probe that is not one");
}

#[tokio::test]
async fn discovery_off_binds_nothing() {
    let server = bench_builder().discovery(false).start().await.unwrap();

    assert!(server.discovery_addr().is_none());
}

/// Sends a probe to `address` and says whether an answer came back within a second.
async fn probe_is_answered(address: std::net::SocketAddr) -> bool {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(&skakel_wire::discovery::create_probe(), address)
        .await
        .unwrap();
    let mut buffer = [0u8; 2048];
    tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut buffer))
        .await
        // On Windows a probe to a closed port comes back as an error, which is no answer.
        .is_ok_and(|received| received.is_ok())
}

/// Sends a probe from `from` to `to` and whether an answer came back to the same socket.
async fn probe_answered_over(from: &str, to: std::net::SocketAddr) -> bool {
    let socket = UdpSocket::bind(from).await.unwrap();
    socket
        .send_to(&skakel_wire::discovery::create_probe(), to)
        .await
        .unwrap();
    let mut buffer = [0u8; 2048];
    match tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buffer)).await {
        Ok(Ok((length, _))) => {
            skakel_wire::discovery::try_parse_answer(&buffer[..length]).is_some()
        }
        _ => false,
    }
}

/// True when this machine can use IPv6 on loopback; a test that needs it says so and passes
/// without it (a container with IPv6 switched off).
async fn has_ipv6_loopback() -> bool {
    let usable = UdpSocket::bind("[::1]:0").await.is_ok();
    if !usable {
        eprintln!("no IPv6 loopback here, so the IPv6 discovery test is skipped");
    }
    usable
}

#[tokio::test]
async fn discovery_answers_probes_over_ipv6_when_https_serves_ipv6() {
    if !has_ipv6_loopback().await {
        return;
    }
    // HTTPS on an IPv6 address and discovery on every IPv4 address: it also answers on an IPv6
    // socket of its own, on the same port, so both families find the server.
    let server = bench_builder()
        .listen("[::1]:0".parse().unwrap())
        .discovery_bind("0.0.0.0".parse().unwrap())
        .start()
        .await
        .unwrap();
    let port = server.discovery_addr().unwrap().port();

    assert!(probe_answered_over("127.0.0.1:0", ([127, 0, 0, 1], port).into()).await);
    assert!(probe_answered_over("[::1]:0", format!("[::1]:{port}").parse().unwrap()).await);
    server.stop_discovery().await;
    assert!(
        !probe_answered_over("[::1]:0", format!("[::1]:{port}").parse().unwrap()).await,
        "stopping releases the IPv6 socket too"
    );
}

#[tokio::test]
async fn discovery_stays_on_ipv4_when_https_is_ipv4_only() {
    if !has_ipv6_loopback().await {
        return;
    }
    let server = bench_builder()
        .discovery_bind("0.0.0.0".parse().unwrap())
        .start()
        .await
        .unwrap();
    let port = server.discovery_addr().unwrap().port();

    assert!(probe_answered_over("127.0.0.1:0", ([127, 0, 0, 1], port).into()).await);
    assert!(
        !probe_answered_over("[::1]:0", format!("[::1]:{port}").parse().unwrap()).await,
        "an IPv6 answer would lead to an address HTTPS does not serve"
    );
}

#[tokio::test]
async fn discovery_binds_an_ipv6_address_when_asked_to() {
    if !has_ipv6_loopback().await {
        return;
    }
    let server = bench_builder()
        .listen("[::1]:0".parse().unwrap())
        .discovery_bind("::1".parse().unwrap())
        .start()
        .await
        .unwrap();
    let address = server.discovery_addr().unwrap();

    assert!(address.is_ipv6());
    assert!(probe_answered_over("[::1]:0", address).await);
}

#[tokio::test]
async fn discovery_can_be_started_after_it_was_built_off() {
    let server = bench_builder().discovery(false).start().await.unwrap();

    let address = server.start_discovery().await.unwrap();

    assert_eq!(server.discovery_addr(), Some(address));
    assert!(probe_is_answered(address).await);
}

#[tokio::test]
async fn discovery_stops_answering_and_frees_its_port_until_started_again() {
    let server = start().await;
    let address = server.discovery_addr().unwrap();

    server.stop_discovery().await;

    assert!(server.discovery_addr().is_none());
    assert!(!probe_is_answered(address).await);
    // The port is free once stop has returned.
    drop(
        UdpSocket::bind(address)
            .await
            .expect("the port is released"),
    );
    let again = server.start_discovery().await.unwrap();
    assert_eq!(again, address, "the same port, so the announcement holds");
    assert!(probe_is_answered(again).await);
}

#[tokio::test]
async fn starting_and_stopping_discovery_twice_changes_nothing() {
    let server = start().await;
    let address = server.discovery_addr().unwrap();

    assert_eq!(server.start_discovery().await.unwrap(), address);
    assert!(probe_is_answered(address).await);
    server.stop_discovery().await;
    server.stop_discovery().await;
    assert!(server.discovery_addr().is_none());
}

#[tokio::test]
async fn starting_discovery_on_a_port_in_use_is_an_error_and_it_stays_off() {
    let taken = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = taken.local_addr().unwrap().port();
    let server = bench_builder()
        .discovery(false)
        .discovery_port(port)
        .start()
        .await
        .unwrap();

    assert!(server.start_discovery().await.is_err());
    assert!(server.discovery_addr().is_none());
    drop(taken);
    assert!(server.start_discovery().await.is_ok());
}

#[tokio::test]
async fn discovery_announces_the_new_fingerprint_after_a_certificate_switch() {
    let server = start().await;
    let address = server.discovery_addr().unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    server
        .certificates()
        .prepare_next_certificate()
        .await
        .unwrap();
    let next = server.certificates().next_fingerprint().unwrap();
    server.certificates().switch_certificate().await.unwrap();

    socket
        .send_to(&skakel_wire::discovery::create_probe(), address)
        .await
        .unwrap();
    let mut buffer = [0u8; 2048];
    let (length, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();

    let answer = skakel_wire::discovery::try_parse_answer(&buffer[..length]).unwrap();
    assert!(fingerprints::are_equal(&answer.fingerprint, &next));
}

// ---- pairing ----

async fn open_pairing(server: &skakel_server::SkakelServer, name: &str) -> (Value, String) {
    let nonce = new_nonce().unwrap();
    let opened = Request::new("POST", "/skakel/v2/pair")
        .json(&json!({ "clientName": name, "commitment": commit(&nonce) }))
        .send(server)
        .await;
    assert_eq!(opened.status, 200, "{}", opened.text());
    (opened.json(), nonce)
}

async fn reveal(server: &skakel_server::SkakelServer, opened: &Value, nonce: &str) -> Reply {
    Request::new(
        "POST",
        &format!(
            "/skakel/v2/pair/{}/reveal",
            opened["requestId"].as_str().unwrap()
        ),
    )
    .json(&json!({ "clientNonce": nonce }))
    .send(server)
    .await
}

async fn poll(server: &skakel_server::SkakelServer, opened: &Value) -> Reply {
    Request::get(&format!(
        "/skakel/v2/pair/{}",
        opened["requestId"].as_str().unwrap()
    ))
    .header("X-Pair-Token", opened["pollToken"].as_str().unwrap())
    .send(server)
    .await
}

#[tokio::test]
async fn pairing_runs_open_reveal_approve_poll_and_the_credentials_sign_in() {
    let server = start().await;
    let (opened, nonce) = open_pairing(&server, "  lab\u{202e} pc ").await;
    assert_eq!(opened["requestId"].as_str().unwrap().len(), 32);
    assert!(opened["expiresAt"].as_str().unwrap().contains('T'));
    assert_eq!(
        poll(&server, &opened).await.json(),
        json!({ "state": "waiting", "clientId": null, "clientSecret": null })
    );
    assert_eq!(reveal(&server, &opened, &nonce).await.status, 204);
    let overview = server.pairing().overview().await;
    assert_eq!(overview.requests.len(), 1);
    assert_eq!(overview.requests[0].client_name, "lab pc");
    assert_eq!(overview.requests[0].from, "127.0.0.1");
    // The code is made from the name as the client sent it, not as the server keeps it.
    let code = compute(
        &server.fingerprint(),
        "  lab\u{202e} pc ",
        &nonce,
        opened["serverNonce"].as_str().unwrap(),
    )
    .unwrap();

    let approval = server
        .pairing()
        .approve(&overview.requests[0].id, &code)
        .await
        .unwrap();

    assert_eq!(approval, Approval::Approved);
    let done = poll(&server, &opened).await.json();
    assert_eq!(done["state"], "approved");
    let (id, secret) = (
        done["clientId"].as_str().unwrap(),
        done["clientSecret"].as_str().unwrap(),
    );
    assert_eq!(
        poll(&server, &opened).await.status,
        404,
        "the credentials are handed over once"
    );
    let token = token_for(&server, id, secret).await;
    let hello = control(&grpc(&server).await)
        .hello(with_token(skakel_proto::v2::HelloRequest {}, &token))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        (hello.server.as_str(), hello.client_id.as_str()),
        ("rust-bench", id)
    );
    assert_eq!(server.clients().name_of(id).as_deref(), Some("lab pc"));
}

#[tokio::test]
async fn the_code_is_made_from_the_name_as_sent_not_the_name_as_kept() {
    // A code worked out from the cleaned name is not the code: the client's screen shows the one
    // made from what it sent, so a name swapped on the way gives a code that does not match.
    let server = start().await;
    let (opened, nonce) = open_pairing(&server, "  lab\u{202e} pc ").await;
    assert_eq!(reveal(&server, &opened, &nonce).await.status, 204);
    let overview = server.pairing().overview().await;
    assert_eq!(overview.requests[0].client_name, "lab pc");
    let from_the_kept_name = compute(
        &server.fingerprint(),
        "lab pc",
        &nonce,
        opened["serverNonce"].as_str().unwrap(),
    )
    .unwrap();

    let approval = server
        .pairing()
        .approve(&overview.requests[0].id, &from_the_kept_name)
        .await
        .unwrap();

    assert_eq!(approval, Approval::WrongCode);
}

#[tokio::test]
async fn the_apps_event_stream_hears_of_a_revealed_request_and_how_it_ended() {
    let server = bench_builder().start().await.unwrap();
    let mut events = server.subscribe();
    let (opened, nonce) = open_pairing(&server, "lab pc").await;
    assert_eq!(reveal(&server, &opened, &nonce).await.status, 204);

    let overview = loop {
        let event = tokio::time::timeout(Duration::from_secs(5), events.recv())
            .await
            .unwrap()
            .unwrap();
        if let ServerEvent::Pairing(overview) = event {
            break overview;
        }
    };
    assert_eq!(overview.requests.len(), 1);
    assert_eq!(overview.requests[0].state, "waiting");

    assert!(server.pairing().deny(&overview.requests[0].id).await);
    assert_eq!(poll(&server, &opened).await.json()["state"], "denied");
    let mut decided = None;
    while let Ok(Some(event)) = tokio::time::timeout(Duration::from_secs(5), events.recv()).await {
        if let ServerEvent::Decided(decision) = event {
            decided = Some(decision);
            break;
        }
    }
    assert_eq!(
        decided.unwrap().refusal.as_deref(),
        Some("Refused on the server.")
    );
}

#[tokio::test]
async fn three_wrong_codes_deny_and_the_poll_says_so() {
    let server = start().await;
    let (opened, nonce) = open_pairing(&server, "lab pc").await;
    reveal(&server, &opened, &nonce).await;
    let id = server.pairing().overview().await.requests[0].id.clone();

    for _ in 0..3 {
        assert_eq!(
            server.pairing().approve(&id, "000000").await.unwrap(),
            Approval::WrongCode
        );
    }

    assert_eq!(poll(&server, &opened).await.json()["state"], "denied");
    assert!(server.clients().all().is_empty());
}

#[tokio::test]
async fn pairing_refuses_what_the_protocol_says_is_a_bad_request() {
    let server = start().await;
    let good = commit(&new_nonce().unwrap());
    let cases: Vec<(Request, &str)> = vec![
        (
            Request::new("POST", "/skakel/v2/pair").form("clientName=a"),
            "no JSON content type",
        ),
        (
            Request::new("POST", "/skakel/v2/pair")
                .json(&json!({ "clientName": "", "commitment": good })),
            "empty name",
        ),
        (
            Request::new("POST", "/skakel/v2/pair")
                .json(&json!({ "clientName": "\u{200b}\n", "commitment": good })),
            "name of format characters",
        ),
        (
            Request::new("POST", "/skakel/v2/pair")
                .json(&json!({ "clientName": "a".repeat(81), "commitment": good })),
            "name over 80",
        ),
        (
            Request::new("POST", "/skakel/v2/pair")
                .json(&json!({ "clientName": "a", "commitment": "abc" })),
            "short commitment",
        ),
        (
            Request::new("POST", "/skakel/v2/pair")
                .json(&json!({ "clientName": "a", "commitment": "Z".repeat(64) })),
            "commitment not hex",
        ),
        (
            Request::new("POST", "/skakel/v2/pair").json(&json!({ "clientName": "a" })),
            "no commitment",
        ),
        (
            Request::new("POST", "/skakel/v2/pair").header("Content-Type", "application/json"),
            "no body",
        ),
    ];

    for (request, what) in cases {
        let reply = request.send(&server).await;
        assert_eq!(reply.status, 400, "{what}: {}", reply.text());
        assert_eq!(
            reply.header("content-type"),
            Some("application/problem+json")
        );
    }

    let eighty = Request::new("POST", "/skakel/v2/pair")
        .json(&json!({ "clientName": "a".repeat(80), "commitment": good }))
        .send(&server)
        .await;
    assert_eq!(eighty.status, 200, "80 characters is fine");
}

#[tokio::test]
async fn an_unknown_request_a_wrong_token_and_a_wrong_nonce_are_all_404() {
    let server = start().await;
    let (opened, nonce) = open_pairing(&server, "lab pc").await;
    let id = opened["requestId"].as_str().unwrap();

    let unknown = Request::get("/skakel/v2/pair/nobody")
        .header("X-Pair-Token", "x")
        .send(&server)
        .await;
    let wrong_token = Request::get(&format!("/skakel/v2/pair/{id}"))
        .header("X-Pair-Token", "x")
        .send(&server)
        .await;
    let no_token = Request::get(&format!("/skakel/v2/pair/{id}"))
        .send(&server)
        .await;
    let wrong_nonce = reveal(&server, &opened, "not-the-nonce").await;
    let no_nonce = Request::new("POST", &format!("/skakel/v2/pair/{id}/reveal"))
        .json(&json!({}))
        .send(&server)
        .await;
    let delete_wrong = Request::new("DELETE", &format!("/skakel/v2/pair/{id}"))
        .header("X-Pair-Token", "x")
        .send(&server)
        .await;

    for (reply, what) in [
        (unknown, "unknown"),
        (wrong_token, "wrong token"),
        (no_token, "no token"),
        (wrong_nonce, "wrong nonce"),
        (no_nonce, "no nonce"),
        (delete_wrong, "delete with a wrong token"),
    ] {
        assert_eq!(reply.status, 404, "{what}");
    }
    assert_eq!(
        reveal(&server, &opened, &nonce).await.status,
        204,
        "the right nonce still works"
    );
}

#[tokio::test]
async fn a_waiting_request_can_be_withdrawn_with_its_token() {
    let server = start().await;
    let (opened, nonce) = open_pairing(&server, "lab pc").await;
    reveal(&server, &opened, &nonce).await;

    let withdrawn = Request::new(
        "DELETE",
        &format!("/skakel/v2/pair/{}", opened["requestId"].as_str().unwrap()),
    )
    .header("X-Pair-Token", opened["pollToken"].as_str().unwrap())
    .send(&server)
    .await;

    assert_eq!(withdrawn.status, 204);
    assert!(server.pairing().overview().await.requests.is_empty());
    assert_eq!(poll(&server, &opened).await.status, 404);
}

#[tokio::test]
async fn an_address_opens_five_requests_and_the_sixth_is_429_with_a_problem() {
    let server = start().await;
    for _ in 0..3 {
        open_pairing(&server, "lab pc").await;
    }

    let fourth = Request::new("POST", "/skakel/v2/pair")
        .json(&json!({ "clientName": "a", "commitment": commit(&new_nonce().unwrap()) }))
        .send(&server)
        .await;

    assert_eq!(
        fourth.status, 429,
        "three open at once is the most from one address"
    );
    assert_eq!(
        fourth.header("content-type"),
        Some("application/problem+json")
    );
}

#[tokio::test]
async fn all_pairing_calls_are_limited_per_address_before_the_body_is_read() {
    let server = bench_builder()
        .pair_requests_per_minute(3)
        .start()
        .await
        .unwrap();

    for _ in 0..3 {
        assert_eq!(
            Request::get("/skakel/v2/pair/nobody")
                .send(&server)
                .await
                .status,
            404
        );
    }
    let over = Request::new("POST", "/skakel/v2/pair")
        .form("not even json")
        .send(&server)
        .await;

    assert_eq!(over.status, 429);
    assert_eq!(
        over.header("content-type"),
        Some("application/problem+json")
    );
}

#[tokio::test]
async fn a_body_over_four_kib_is_413_when_declared_and_400_when_found_out_while_reading() {
    let server = start().await;
    let big = "x".repeat(5000);

    let mut declared = Request::new("POST", "/skakel/v2/pair")
        .json(&json!({ "clientName": big, "commitment": "A" }));
    declared.declared_length = None;
    let declared = declared.send(&server).await;
    let mut token = Request::new("POST", "/skakel/v2/token").form(&format!(
        "grant_type=client_credentials&client_id=a&client_secret={big}"
    ));
    token.declared_length = None;
    let token = token.send(&server).await;

    assert_eq!(declared.status, 413);
    assert_eq!(token.status, 413);
    assert_eq!(
        token.header("content-type"),
        Some("application/problem+json")
    );

    // A body sent in chunks has no length to check, so the cap cuts it off while it is read.
    let (stream, _) = tls(server.local_addr(), true).await;
    let mut raw = b"POST /skakel/v2/token HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    for _ in 0..3 {
        raw.extend_from_slice(format!("{:x}\r\n{}\r\n", 2000, "a".repeat(2000)).as_bytes());
    }
    raw.extend_from_slice(b"0\r\n\r\n");
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = stream;
    stream.write_all(&raw).await.unwrap();
    let mut answer = vec![];
    let _ = stream.read_to_end(&mut answer).await;
    assert!(
        String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 400"),
        "{}",
        String::from_utf8_lossy(&answer)
    );
}

// ---- tokens ----

#[tokio::test]
async fn the_token_endpoint_issues_a_thirty_minute_token_for_the_client_and_its_generation() {
    let server = start().await;
    let client = server.clients().register("bench-1").await.unwrap();

    let reply = token_request(&server, &client.client_id, &client.client_secret).await;

    assert_eq!(reply.status, 200);
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    let body = reply.json();
    assert_eq!(body["token_type"], "Bearer");
    let expires_in = body["expires_in"].as_i64().unwrap();
    assert!((1795..=1800).contains(&expires_in), "{expires_in}");
    let token = body["access_token"].as_str().unwrap();
    // An opaque token: 256 random bits as hex, not something a client can read.
    assert_eq!(token.len(), 64, "{token}");
    assert!(token.bytes().all(|b| b.is_ascii_hexdigit()), "{token}");
}

#[tokio::test]
async fn a_wrong_secret_and_an_unknown_client_look_the_same() {
    let server = start().await;
    let client = server.clients().register("bench-1").await.unwrap();

    let wrong = token_request(&server, &client.client_id, "not-the-secret").await;
    let unknown = token_request(&server, "client-nobody", &client.client_secret).await;

    assert_eq!(wrong.status, 401);
    assert_eq!(wrong.json()["error"], "invalid_client");
    assert_eq!(wrong.text(), unknown.text());
}

#[tokio::test]
async fn the_token_endpoint_takes_http_basic_credentials_and_refuses_other_grants() {
    let server = start().await;
    let client = server.clients().register("bench-1").await.unwrap();
    let basic = base64::engine::general_purpose::STANDARD
        .encode(format!("{}:{}", client.client_id, client.client_secret));

    let with_basic = Request::new("POST", "/skakel/v2/token")
        .header("Authorization", format!("Basic {basic}"))
        .form("grant_type=client_credentials")
        .send(&server)
        .await;
    let password = Request::new("POST", "/skakel/v2/token")
        .form("grant_type=password&username=a&password=b")
        .send(&server)
        .await;
    let not_a_form = Request::new("POST", "/skakel/v2/token")
        .json(&json!({}))
        .send(&server)
        .await;
    let no_secret = Request::new("POST", "/skakel/v2/token")
        .form(&format!(
            "grant_type=client_credentials&client_id={}",
            client.client_id
        ))
        .send(&server)
        .await;

    assert_eq!(with_basic.status, 200);
    assert_eq!(password.status, 400);
    assert_eq!(password.json()["error"], "unsupported_grant_type");
    assert_eq!(not_a_form.status, 400);
    assert_eq!(not_a_form.json()["error"], "invalid_request");
    assert_eq!(no_secret.status, 401);
}

#[tokio::test]
async fn ten_wrong_secrets_stop_a_client_from_any_address_even_with_the_right_one() {
    let server = start().await;
    let client = server.clients().register("bench-1").await.unwrap();
    let other = server.clients().register("bench-2").await.unwrap();

    for _ in 0..10 {
        assert_eq!(
            token_request(&server, &client.client_id, "wrong")
                .await
                .status,
            401
        );
    }

    let stopped = token_request(&server, &client.client_id, &client.client_secret).await;
    assert_eq!(stopped.status, 429);
    assert_eq!(
        stopped.header("content-type"),
        Some("application/problem+json")
    );
    assert_eq!(
        token_request(&server, &other.client_id, &other.client_secret)
            .await
            .status,
        200,
        "another client is not affected"
    );
}

#[tokio::test]
async fn made_up_client_ids_do_not_fill_the_failure_limiter() {
    let server = start().await;
    let client = server.clients().register("bench-1").await.unwrap();

    for i in 0..12 {
        assert_eq!(
            token_request(&server, &format!("client-fake{i}"), "x")
                .await
                .status,
            401
        );
    }

    assert_eq!(
        token_request(&server, &client.client_id, &client.client_secret)
            .await
            .status,
        200
    );
}

#[tokio::test]
async fn the_token_endpoint_takes_a_limited_number_of_requests_a_minute_from_one_address() {
    let server = bench_builder()
        .token_requests_per_minute(3)
        .start()
        .await
        .unwrap();
    let client = server.clients().register("bench-1").await.unwrap();

    for _ in 0..3 {
        assert_eq!(
            token_request(&server, &client.client_id, &client.client_secret)
                .await
                .status,
            200
        );
    }
    let over = token_request(&server, &client.client_id, &client.client_secret).await;

    assert_eq!(over.status, 429);
    assert_eq!(
        over.header("content-type"),
        Some("application/problem+json")
    );
}

#[tokio::test]
async fn the_token_servers_discovery_documents_are_not_served() {
    let server = start().await;

    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/jwks",
        "/skakel/v2/jwks",
    ] {
        assert_eq!(Request::get(path).send(&server).await.status, 404, "{path}");
    }
}

#[tokio::test]
async fn the_apps_own_routes_take_the_same_bearer_token() {
    async fn mine(ClientPrincipal(principal): ClientPrincipal) -> String {
        principal.client_id
    }
    let routes = axum::Router::new().route("/app/mine", axum::routing::get(mine));
    let server = bench_builder().routes(routes).start().await.unwrap();
    let (client, token) = client_with_token(&server, "bench-1").await;

    let allowed = Request::get("/app/mine").bearer(&token).send(&server).await;
    let refused = Request::get("/app/mine").send(&server).await;
    server.clients().revoke(&client.client_id).await.unwrap();
    let revoked = Request::get("/app/mine").bearer(&token).send(&server).await;

    assert_eq!((allowed.status, allowed.text()), (200, client.client_id));
    assert_eq!(refused.status, 401);
    assert_eq!(revoked.status, 401);
}

// ---- the certificate ----

#[tokio::test]
async fn the_server_presents_its_certificate_and_a_handover_changes_it_only_at_the_switch() {
    let server = start().await;
    let current = server.fingerprint();
    assert!(fingerprints::are_equal(
        &presented_fingerprint(server.local_addr()).await,
        &current
    ));

    let next = server
        .certificates()
        .prepare_next_certificate()
        .await
        .unwrap()
        .unwrap();

    assert!(
        fingerprints::are_equal(&presented_fingerprint(server.local_addr()).await, &current),
        "still the current one"
    );
    assert_ne!(next, current);
    let switched = server
        .certificates()
        .switch_certificate()
        .await
        .unwrap()
        .unwrap();
    assert!(fingerprints::are_equal(
        &presented_fingerprint(server.local_addr()).await,
        &next
    ));
    assert_eq!(switched.from, current);
}

// ---- state kept between runs ----

#[tokio::test]
async fn a_server_started_again_on_the_same_file_has_the_same_certificate_and_clients() {
    let folder = std::env::temp_dir().join(format!("skakel-server-test-{}", std::process::id()));
    let file = folder.join("state.json");
    let start_on_file = || async {
        SkakelServerBuilder::new(APP_ID, APP_VERSION, skakel_server::FileStore::new(&file))
            .listen("127.0.0.1:0".parse().unwrap())
            .discovery(false)
            .start()
            .await
            .unwrap()
    };
    let first = start_on_file().await;
    let fingerprint = first.fingerprint();
    let client = first.clients().register("bench-1").await.unwrap();
    first.shutdown().await;

    let second = start_on_file().await;

    assert_eq!(second.fingerprint(), fingerprint);
    assert_eq!(
        token_request(&second, &client.client_id, &client.client_secret)
            .await
            .status,
        200
    );
    assert!(fingerprints::are_equal(
        &presented_fingerprint(second.local_addr()).await,
        &fingerprint
    ));
    second.shutdown().await;
    let _ = std::fs::remove_dir_all(folder);
}

#[tokio::test]
async fn the_state_on_disk_holds_the_hash_of_a_secret_and_not_the_secret() {
    let store = std::sync::Arc::new(InMemoryStore::new());
    let server = bench_builder_with(store.clone()).start().await.unwrap();

    let client = server.clients().register("bench-1").await.unwrap();

    let saved = store.state().unwrap();
    assert!(
        !serde_json::to_string(&saved)
            .unwrap()
            .contains(&client.client_secret)
    );
    assert!(server.clients().secret_of(&client.client_id).is_none());
    let keeping = bench_builder()
        .keep_client_secrets(true)
        .start()
        .await
        .unwrap();
    let kept = keeping.clients().register("bench-1").await.unwrap();
    assert_eq!(
        keeping.clients().secret_of(&kept.client_id),
        Some(kept.client_secret)
    );
}

#[tokio::test]
async fn after_shutdown_the_port_is_closed() {
    let server = start().await;
    let address = server.local_addr();

    server.shutdown().await;

    assert!(tokio::net::TcpStream::connect(address).await.is_err());
}
