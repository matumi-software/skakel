//! The server mounted on an app's own server, as an app that serves its own pages on Skakel's port
//! runs it: an axum router with a page of the app's own and Skakel's service as its fallback, a TLS
//! acceptor from the server's settings and Skakel's connection settings (see
//! `common::start_mounted_with`). Clients reach Skakel through the app's port.

mod common;

use std::time::Duration;

use axum::extract::ConnectInfo;
use common::greeter::{self, GreetRequest};
use common::*;
use serde_json::{Value, json};
use skakel_proto::v3::{HelloRequest, connect_response, open_response};
use skakel_server::{Approval, OptionProblem, ServerError, SkakelServerBuilder};
use skakel_wire::fingerprints;
use skakel_wire::pairing::{commit, compute, new_nonce};
use tokio::net::UdpSocket;
use tonic::Code;
use tower_service::Service;

/// Opens a pairing request from the local address `from`.
async fn open_pairing_from(server: &skakel_server::SkakelServer, from: &str) -> Reply {
    Request::new("POST", "/skakel/v3/pair")
        .json(&json!({ "clientName": "lab pc", "commitment": commit(&new_nonce().unwrap()) }))
        .send_from(server, from)
        .await
}

#[tokio::test]
async fn an_apps_own_server_serves_its_page_and_skakels_pairing_tokens_control_and_streams() {
    let server = start_mounted().await;

    let page = Request::get(APP_PAGE).send(&server).await;
    let info = Request::get("/skakel/info").send(&server).await;
    assert_eq!(
        (page.status, page.text()),
        (200, "the app's own page".into())
    );
    assert_eq!(info.status, 200);
    assert_eq!(info.json()["name"], NAME);

    // Pairing, through the app's port.
    let nonce = new_nonce().unwrap();
    let opened = Request::new("POST", "/skakel/v3/pair")
        .json(&json!({ "clientName": "lab pc", "commitment": commit(&nonce) }))
        .send(&server)
        .await
        .json();
    let id = opened["requestId"].as_str().unwrap();
    let revealed = Request::new("POST", &format!("/skakel/v3/pair/{id}/reveal"))
        .json(&json!({ "clientNonce": nonce }))
        .send(&server)
        .await;
    assert_eq!(revealed.status, 204);
    let overview = server.pairing().overview().await;
    assert_eq!(overview.requests[0].from, "127.0.0.1");
    let code = compute(
        &server.fingerprint(),
        "lab pc",
        &nonce,
        opened["serverNonce"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(
        server.pairing().approve(id, &code).await.unwrap(),
        Approval::Approved
    );
    let done: Value = Request::get(&format!("/skakel/v3/pair/{id}"))
        .header("X-Pair-Token", opened["pollToken"].as_str().unwrap())
        .send(&server)
        .await
        .json();
    assert_eq!(done["state"], "approved");

    // A token, then the control channel, a stream and the app's own service on one connection.
    let client_id = done["clientId"].as_str().unwrap();
    let token = token_for(&server, client_id, done["clientSecret"].as_str().unwrap()).await;
    let connection = grpc(&server).await;
    assert_eq!(connection.alpn.as_deref(), Some(&b"h2"[..]));
    let hello = control(&connection)
        .hello(with_token(HelloRequest {}, &token))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(hello.client_id, client_id);
    let mut call = connect(&connection, &token).await.unwrap();
    assert!(matches!(
        call.next().await.unwrap(),
        Some(connect_response::Message::Certificates(_))
    ));
    let mut stream = open_stream_on(&connection, &token, "echo", b"a b")
        .await
        .unwrap();
    stream.send_data(&b"ping"[..]).await;
    assert_eq!(
        stream.next().await.unwrap(),
        Some(open_response::Frame::Data(b"ping"[..].into()))
    );
    let reply = greeter::greet(
        connection.clone(),
        with_token(GreetRequest { text: "hi".into() }, &token),
    )
    .await
    .unwrap();
    assert_eq!(reply.text, format!("{client_id}: hi"));
}

#[tokio::test]
async fn pairing_limits_count_each_callers_address_apart() {
    let server = start_mounted().await;
    for _ in 0..3 {
        assert_eq!(open_pairing_from(&server, "127.0.0.1").await.status, 200);
    }

    let fourth = open_pairing_from(&server, "127.0.0.1").await;
    let other = open_pairing_from(&server, "127.0.0.2").await;

    assert_eq!(
        fourth.status, 429,
        "three open at once is the most from one address"
    );
    assert_eq!(other.status, 200, "another address has its own limit");
}

#[tokio::test]
async fn a_pairing_request_shows_the_address_it_came_from() {
    let server = start_mounted().await;
    let nonce = new_nonce().unwrap();
    let opened = Request::new("POST", "/skakel/v3/pair")
        .json(&json!({ "clientName": "lab pc", "commitment": commit(&nonce) }))
        .send_from(&server, "127.0.0.2")
        .await
        .json();

    let revealed = Request::new(
        "POST",
        &format!(
            "/skakel/v3/pair/{}/reveal",
            opened["requestId"].as_str().unwrap()
        ),
    )
    .json(&json!({ "clientNonce": nonce }))
    .send(&server)
    .await;

    assert_eq!(revealed.status, 204);
    assert_eq!(
        server.pairing().overview().await.requests[0].from,
        "127.0.0.2"
    );
}

#[tokio::test]
async fn pairing_calls_a_minute_are_counted_per_callers_address() {
    let server = start_mounted_with(bench_builder().pair_requests_per_minute(2)).await;
    for _ in 0..2 {
        let reply = Request::get("/skakel/v3/pair/nobody")
            .send_from(&server, "127.0.0.1")
            .await;
        assert_eq!(reply.status, 404);
    }

    let over = Request::get("/skakel/v3/pair/nobody")
        .send_from(&server, "127.0.0.1")
        .await;
    let other = Request::get("/skakel/v3/pair/nobody")
        .send_from(&server, "127.0.0.2")
        .await;

    assert_eq!(over.status, 429);
    assert_eq!(other.status, 404, "another address has its own minute");
}

#[tokio::test]
async fn token_requests_a_minute_are_counted_per_callers_address() {
    let server = start_mounted_with(bench_builder().token_requests_per_minute(2)).await;
    let client = server.clients().register("bench-1").await.unwrap();
    let request = || {
        Request::new("POST", "/skakel/v3/token").form(&format!(
            "grant_type=client_credentials&client_id={}&client_secret={}",
            client.client_id, client.client_secret
        ))
    };
    for _ in 0..2 {
        assert_eq!(request().send_from(&server, "127.0.0.1").await.status, 200);
    }

    let over = request().send_from(&server, "127.0.0.1").await;
    let other = request().send_from(&server, "127.0.0.2").await;

    assert_eq!(over.status, 429);
    assert_eq!(other.status, 200, "another address has its own minute");
}

#[tokio::test]
async fn a_request_without_the_callers_address_is_refused_rather_than_counted_with_others() {
    let server = bench_builder()
        .discovery(false)
        .start_mounted("127.0.0.1:5240".parse().unwrap())
        .await
        .unwrap();
    let mut service = server.service();
    let https = axum::http::Request::get("/skakel/info")
        .body(axum::body::Body::empty())
        .unwrap();
    let grpc = axum::http::Request::post("/skakel.v3.ControlService/Hello")
        .header("content-type", "application/grpc")
        .body(axum::body::Body::empty())
        .unwrap();
    let mut with_address = axum::http::Request::get("/skakel/info")
        .body(axum::body::Body::empty())
        .unwrap();
    with_address
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            [10, 0, 0, 1],
            50000,
        ))));

    let https = service.call(https).await.unwrap();
    let grpc = service.call(grpc).await.unwrap();
    let with_address = service.call(with_address).await.unwrap();

    assert_eq!(https.status(), 500);
    assert_eq!(https.headers()["content-type"], "application/problem+json");
    assert_eq!(grpc.headers()["grpc-status"], "13", "INTERNAL");
    assert_eq!(with_address.status(), 200);
}

#[tokio::test]
async fn a_route_that_takes_the_client_but_sits_on_the_apps_router_is_refused_not_a_panic() {
    async fn mine(
        skakel_server::ClientPrincipal(principal): skakel_server::ClientPrincipal,
    ) -> String {
        principal.client_id
    }
    let server = bench_builder()
        .discovery(false)
        .start_mounted("127.0.0.1:5240".parse().unwrap())
        .await
        .unwrap();
    // The route is on the app's own router instead of given to the builder's `routes`, so
    // Skakel's state is not on its requests.
    let mut app = axum::Router::new()
        .route("/app/mine", axum::routing::get(mine))
        .fallback_service(server.service());
    let mut request = axum::http::Request::get("/app/mine")
        .header("authorization", "Bearer any")
        .body(axum::body::Body::empty())
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            [10, 0, 0, 1],
            50000,
        ))));

    let answer = app.call(request).await.unwrap();

    assert_eq!(answer.status(), 500);
    assert_eq!(answer.headers()["content-type"], "application/problem+json");
    let body = axum::body::to_bytes(answer.into_body(), 4096)
        .await
        .unwrap();
    let problem: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        problem["detail"].as_str().unwrap().contains("routes"),
        "{problem}"
    );
}

#[tokio::test]
async fn the_apps_acceptor_presents_the_certificate_and_a_handover_changes_it_only_at_the_switch() {
    let server = start_mounted().await;
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
    server
        .certificates()
        .switch_certificate()
        .await
        .unwrap()
        .unwrap();
    assert!(fingerprints::are_equal(
        &presented_fingerprint(server.local_addr()).await,
        &next
    ));
}

#[tokio::test]
async fn the_apps_acceptor_shows_the_certificate_on_every_connection_because_no_session_is_resumed()
{
    let server = start_mounted().await;
    // One client config for both connections, so the second would resume the first's session if
    // the app's acceptor allowed it, and its handshake would show no certificate.
    let (config, verifier) = tls_config(&[b"http/1.1"]);
    let first = tls_with(server.local_addr(), config.clone()).await;
    // A whole exchange on the first, so any session ticket would have arrived.
    let info = {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut first = first;
        first
            .write_all(&Request::get("/skakel/info").bytes())
            .await
            .unwrap();
        let mut raw = vec![];
        let _ = first.read_to_end(&mut raw).await;
        raw
    };
    assert!(info.starts_with(b"HTTP/1.1 200"));
    *verifier.presented.lock().unwrap() = None;

    let _second = tls_with(server.local_addr(), config).await;

    assert!(verifier.presented.lock().unwrap().is_some());
}

#[tokio::test]
async fn after_shutdown_the_service_ends_calls_and_answers_stopping() {
    let server = start_mounted().await;
    let address = server.local_addr();
    let (_, token) = client_with_token(&server, "bench-1").await;
    let mut call = connect(&grpc(&server).await, &token).await.unwrap();
    call.next().await.unwrap();

    server.shutdown().await;

    let ended = loop {
        match call.next().await {
            Ok(Some(_)) => continue,
            Ok(None) => panic!("the control call ended with OK"),
            Err(status) => break status,
        }
    };
    assert_eq!(refused(&ended), (Code::Unavailable, "STOPPING".into()));
    let page = Request::get(APP_PAGE).send_to(address).await;
    let info = Request::get("/skakel/info").send_to(address).await;
    let hello = control(&grpc_to(address).await)
        .hello(with_token(HelloRequest {}, &token))
        .await
        .unwrap_err();
    assert_eq!(page.status, 200, "the app's own page goes on");
    assert_eq!(info.status, 503);
    assert_eq!(refused(&hello), (Code::Unavailable, "STOPPING".into()));
}

#[tokio::test]
async fn discovery_announces_the_apps_port() {
    let server = start_mounted().await;
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

    assert_eq!(answer.port, server.local_addr().port());
    assert!(fingerprints::are_equal(
        &answer.fingerprint,
        &server.fingerprint()
    ));
}

#[tokio::test]
async fn a_mounted_server_with_discovery_needs_the_port_the_app_bound() {
    let started =
        SkakelServerBuilder::new(APP_ID, APP_VERSION, skakel_server::InMemoryStore::new())
            .start_mounted("0.0.0.0:0".parse().unwrap())
            .await;

    let Err(ServerError::Options(problems)) = started else {
        panic!("a mounted server on port 0 with discovery started");
    };
    assert_eq!(problems, [OptionProblem::DiscoveryPort]);
}
