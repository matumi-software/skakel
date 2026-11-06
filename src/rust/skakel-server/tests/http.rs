//! The server over TLS on loopback, as a client sees it: info, pairing, tokens, hello, the limits,
//! the hub's protocol, streams, discovery and the certificate handover. No .NET needed; the
//! .NET client's side is in `dotnet_interop.rs`.

mod common;

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::*;
use futures_util::SinkExt;
use serde_json::{Value, json};
use skakel_pairing::{commit, compute, new_nonce};
use skakel_protocol::fingerprints;
use skakel_server::{Approval, ClientPrincipal, InMemoryStore, ServerEvent, SkakelServerBuilder};
use tokio::net::UdpSocket;
use tokio_tungstenite::tungstenite::Message;

fn part(token: &str, index: usize) -> Value {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(token.split('.').nth(index).unwrap())
            .unwrap(),
    )
    .unwrap()
}

// ---- info and discovery ----

#[tokio::test]
async fn info_is_served_without_a_token_in_the_shape_the_protocol_shows() {
    let server = start().await;

    let reply = Request::get("/skakel/info").send(&server).await;

    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.text(),
        r#"{"name":"rust-bench","app":{"id":"test-app","version":"1.2.3"},"versions":[1]}"#
    );
}

#[tokio::test]
async fn a_server_with_bad_options_does_not_start_and_says_what_is_wrong() {
    let error = match SkakelServerBuilder::new("Bad App", " ", InMemoryStore::new())
        .token_requests_per_minute(0)
        .hub("/hub/", TestHub)
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
    assert!(error.contains("hub path"), "{error}");
    assert!(error.contains("stream type"), "{error}");
}

#[tokio::test]
async fn a_plain_http_request_to_the_port_is_told_to_use_https() {
    let server = start().await;

    let reply = Request::new("POST", "/skakel/v1/pair")
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
        .send_to(&skakel_discovery::create_probe(), address)
        .await
        .unwrap();
    let mut buffer = [0u8; 2048];
    let (length, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buffer))
        .await
        .expect("an answer")
        .unwrap();
    let answer = skakel_discovery::try_parse_answer(&buffer[..length]).expect("a valid answer");

    assert_eq!(answer.name, "rust-bench");
    assert_eq!(answer.port, server.local_addr().port());
    assert_eq!(answer.app.id, "test-app");
    assert_eq!(answer.versions, [1]);
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

#[tokio::test]
async fn discovery_announces_the_new_fingerprint_after_a_certificate_switch() {
    let server = start().await;
    let address = server.discovery_addr().unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    server.keys().prepare_next_certificate().await.unwrap();
    let next = server.keys().next_fingerprint().unwrap();
    server.keys().switch_certificate().await.unwrap();

    socket
        .send_to(&skakel_discovery::create_probe(), address)
        .await
        .unwrap();
    let mut buffer = [0u8; 2048];
    let (length, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();

    let answer = skakel_discovery::try_parse_answer(&buffer[..length]).unwrap();
    assert!(fingerprints::are_equal(&answer.fingerprint, &next));
}

// ---- pairing ----

async fn open_pairing(server: &skakel_server::SkakelServer, name: &str) -> (Value, String) {
    let nonce = new_nonce();
    let opened = Request::new("POST", "/skakel/v1/pair")
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
            "/skakel/v1/pair/{}/reveal",
            opened["requestId"].as_str().unwrap()
        ),
    )
    .json(&json!({ "clientNonce": nonce }))
    .send(server)
    .await
}

async fn poll(server: &skakel_server::SkakelServer, opened: &Value) -> Reply {
    Request::get(&format!(
        "/skakel/v1/pair/{}",
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
    let code = compute(
        &server.fingerprint(),
        &nonce,
        opened["serverNonce"].as_str().unwrap(),
    );

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
    let hello = Request::get("/skakel/v1/hello")
        .bearer(&token)
        .send(&server)
        .await;
    assert_eq!(
        hello.json(),
        json!({ "server": "rust-bench", "clientId": id })
    );
    assert_eq!(server.clients().name_of(id).as_deref(), Some("lab pc"));
}

#[tokio::test]
async fn the_apps_callback_hears_of_a_revealed_request_and_how_it_ended() {
    let (sender, mut heard) = tokio::sync::mpsc::unbounded_channel();
    let server = bench_builder()
        .on_pairing(move |overview| {
            let _ = sender.send(overview.clone());
        })
        .start()
        .await
        .unwrap();
    let mut events = server.subscribe();
    let (opened, nonce) = open_pairing(&server, "lab pc").await;
    assert_eq!(reveal(&server, &opened, &nonce).await.status, 204);

    let overview = tokio::time::timeout(Duration::from_secs(5), heard.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(overview.requests.len(), 1);
    assert_eq!(overview.requests[0].state, "waiting");

    assert!(server.pairing().deny(&overview.requests[0].id).await);
    assert_eq!(poll(&server, &opened).await.json()["state"], "denied");
    let mut decided = None;
    while let Ok(Ok(event)) = tokio::time::timeout(Duration::from_secs(5), events.recv()).await {
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
    let good = commit(&new_nonce());
    let cases: Vec<(Request, &str)> = vec![
        (
            Request::new("POST", "/skakel/v1/pair").form("clientName=a"),
            "no JSON content type",
        ),
        (
            Request::new("POST", "/skakel/v1/pair")
                .json(&json!({ "clientName": "", "commitment": good })),
            "empty name",
        ),
        (
            Request::new("POST", "/skakel/v1/pair")
                .json(&json!({ "clientName": "\u{200b}\n", "commitment": good })),
            "name of format characters",
        ),
        (
            Request::new("POST", "/skakel/v1/pair")
                .json(&json!({ "clientName": "a".repeat(81), "commitment": good })),
            "name over 80",
        ),
        (
            Request::new("POST", "/skakel/v1/pair")
                .json(&json!({ "clientName": "a", "commitment": "abc" })),
            "short commitment",
        ),
        (
            Request::new("POST", "/skakel/v1/pair")
                .json(&json!({ "clientName": "a", "commitment": "Z".repeat(64) })),
            "commitment not hex",
        ),
        (
            Request::new("POST", "/skakel/v1/pair").json(&json!({ "clientName": "a" })),
            "no commitment",
        ),
        (
            Request::new("POST", "/skakel/v1/pair").header("Content-Type", "application/json"),
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

    let eighty = Request::new("POST", "/skakel/v1/pair")
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

    let unknown = Request::get("/skakel/v1/pair/nobody")
        .header("X-Pair-Token", "x")
        .send(&server)
        .await;
    let wrong_token = Request::get(&format!("/skakel/v1/pair/{id}"))
        .header("X-Pair-Token", "x")
        .send(&server)
        .await;
    let no_token = Request::get(&format!("/skakel/v1/pair/{id}"))
        .send(&server)
        .await;
    let wrong_nonce = reveal(&server, &opened, "not-the-nonce").await;
    let no_nonce = Request::new("POST", &format!("/skakel/v1/pair/{id}/reveal"))
        .json(&json!({}))
        .send(&server)
        .await;
    let delete_wrong = Request::new("DELETE", &format!("/skakel/v1/pair/{id}"))
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
        &format!("/skakel/v1/pair/{}", opened["requestId"].as_str().unwrap()),
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

    let fourth = Request::new("POST", "/skakel/v1/pair")
        .json(&json!({ "clientName": "a", "commitment": commit(&new_nonce()) }))
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
            Request::get("/skakel/v1/pair/nobody")
                .send(&server)
                .await
                .status,
            404
        );
    }
    let over = Request::new("POST", "/skakel/v1/pair")
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

    let mut declared = Request::new("POST", "/skakel/v1/pair")
        .json(&json!({ "clientName": big, "commitment": "A" }));
    declared.declared_length = None;
    let declared = declared.send(&server).await;
    let mut token = Request::new("POST", "/skakel/v1/token").form(&format!(
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
    let mut raw = b"POST /skakel/v1/token HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
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
    let claims = part(token, 1);
    assert_eq!(claims["sub"], client.client_id.as_str());
    assert_eq!(claims["skakel_generation"], "1");
    assert_eq!(claims["iss"], "https://skakel.invalid/");
    assert_eq!(
        part(token, 0)["kid"],
        server.keys().view().signing_key_id.as_str()
    );
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

    let with_basic = Request::new("POST", "/skakel/v1/token")
        .header("Authorization", format!("Basic {basic}"))
        .form("grant_type=client_credentials")
        .send(&server)
        .await;
    let password = Request::new("POST", "/skakel/v1/token")
        .form("grant_type=password&username=a&password=b")
        .send(&server)
        .await;
    let not_a_form = Request::new("POST", "/skakel/v1/token")
        .json(&json!({}))
        .send(&server)
        .await;
    let no_secret = Request::new("POST", "/skakel/v1/token")
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
async fn hello_wants_a_current_token_and_a_revoked_or_rotated_client_loses_its_tokens_at_once() {
    let server = start().await;
    let (client, token) = client_with_token(&server, "bench-1").await;
    assert_eq!(
        Request::get("/skakel/v1/hello")
            .bearer(&token)
            .send(&server)
            .await
            .status,
        200
    );
    assert_eq!(
        Request::get("/skakel/v1/hello").send(&server).await.status,
        401
    );
    assert_eq!(
        Request::get("/skakel/v1/hello")
            .bearer("a.b.c")
            .send(&server)
            .await
            .status,
        401
    );

    let secret = server
        .clients()
        .rotate_secret(&client.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        Request::get("/skakel/v1/hello")
            .bearer(&token)
            .send(&server)
            .await
            .status,
        401,
        "rotated"
    );
    assert_eq!(
        token_request(&server, &client.client_id, &client.client_secret)
            .await
            .status,
        401,
        "the old secret"
    );
    let renewed = token_for(&server, &client.client_id, &secret).await;
    assert_eq!(part(&renewed, 1)["skakel_generation"], "2");
    assert_eq!(
        Request::get("/skakel/v1/hello")
            .bearer(&renewed)
            .send(&server)
            .await
            .status,
        200
    );

    assert!(server.clients().revoke(&client.client_id).await.unwrap());
    assert_eq!(
        Request::get("/skakel/v1/hello")
            .bearer(&renewed)
            .send(&server)
            .await
            .status,
        401,
        "revoked"
    );
}

#[tokio::test]
async fn a_token_from_before_a_signing_key_rotation_still_works_and_one_from_after_does_too() {
    let server = start().await;
    let (client, old) = client_with_token(&server, "bench-1").await;

    server.keys().rotate_signing_key().await.unwrap();
    let new = token_for(&server, &client.client_id, &client.client_secret).await;

    assert_eq!(
        Request::get("/skakel/v1/hello")
            .bearer(&old)
            .send(&server)
            .await
            .status,
        200
    );
    assert_eq!(
        Request::get("/skakel/v1/hello")
            .bearer(&new)
            .send(&server)
            .await
            .status,
        200
    );
    assert_ne!(part(&old, 0)["kid"], part(&new, 0)["kid"]);
}

#[tokio::test]
async fn a_token_works_under_every_name_and_address_of_the_server() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;

    for host in ["localhost", "127.0.0.1", "some.other.name"] {
        let (stream, _) = tls(server.local_addr(), true).await;
        let mut request = Request::get("/skakel/v1/hello").bearer(&token);
        request.headers.push(("X-Host-Was", host.to_owned()));
        let reply = {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut stream = stream;
            let text = String::from_utf8(request.bytes())
                .unwrap()
                .replace("Host: localhost", &format!("Host: {host}"));
            stream.write_all(text.as_bytes()).await.unwrap();
            let mut raw = vec![];
            let _ = stream.read_to_end(&mut raw).await;
            String::from_utf8_lossy(&raw).into_owned()
        };
        assert!(reply.starts_with("HTTP/1.1 200"), "{host}: {reply}");
    }
}

#[tokio::test]
async fn the_token_servers_discovery_documents_are_not_served() {
    let server = start().await;

    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/jwks",
        "/skakel/v1/jwks",
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

// ---- the hub ----

#[tokio::test]
async fn the_hub_negotiates_only_for_a_client_with_a_token_and_only_websockets() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;

    let refused = Request::new("POST", "/skakel/v1/hub/negotiate?negotiateVersion=1")
        .send(&server)
        .await;
    let v1 = Request::new("POST", "/skakel/v1/hub/negotiate?negotiateVersion=1")
        .bearer(&token)
        .send(&server)
        .await;
    let v0 = Request::new("POST", "/skakel/v1/hub/negotiate")
        .bearer(&token)
        .send(&server)
        .await;

    assert_eq!(refused.status, 401);
    let v1 = v1.json();
    assert_eq!(v1["negotiateVersion"], 1);
    assert_ne!(v1["connectionId"], v1["connectionToken"]);
    assert_eq!(v1["availableTransports"][0]["transport"], "WebSockets");
    assert!(v0.json().get("connectionToken").is_none());
    assert!(v0.json()["connectionId"].is_string());
}

#[tokio::test]
async fn a_hub_connection_needs_a_negotiation_a_token_and_a_websocket() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;

    let no_token = open_socket(&server, "/skakel/v1/hub?id=x", None)
        .await
        .err()
        .unwrap();
    let no_negotiation = open_socket(&server, "/skakel/v1/hub?id=x", Some(&token))
        .await
        .err()
        .unwrap();
    let not_a_socket = Request::get("/skakel/v1/hub?id=x")
        .bearer(&token)
        .send(&server)
        .await;

    assert_eq!(no_token.status, 401);
    assert_eq!(no_negotiation.status, 404);
    assert_eq!(not_a_socket.status, 400);
}

#[tokio::test]
async fn the_hub_greets_a_new_connection_with_the_certificates_and_pings() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;

    let mut hub = hub_connect(&server, &token).await;
    let first = hub.next_message().await.unwrap();

    assert_eq!(first["type"], 1);
    assert_eq!(first["target"], "SkakelCertificates");
    assert_eq!(
        first["arguments"][0],
        json!({ "fingerprint": server.fingerprint(), "nextFingerprint": null })
    );
}

#[tokio::test]
async fn hub_calls_return_results_errors_and_messages_back_to_the_caller() {
    let server = start().await;
    let (client, token) = client_with_token(&server, "bench-1").await;
    let mut hub = hub_connect(&server, &token).await;
    hub.next_message().await;

    let echo = hub.invoke("1", "Echo", json!(["hello"])).await;
    let missing = hub.invoke("2", "NoSuchMethod", json!([])).await;
    let skakel_own = hub.invoke("3", "SkakelSomething", json!([])).await;
    hub.send(json!({ "type": 1, "target": "Greet", "arguments": ["hi"] }))
        .await;
    let greeted = hub.next_non_ping().await.unwrap();
    let after = hub.invoke("4", "Echo", json!(["still here"])).await;

    assert_eq!(echo["result"], "hello");
    assert!(echo.get("error").is_none());
    assert_eq!(missing["error"], "Method does not exist.");
    assert!(
        skakel_own["error"]
            .as_str()
            .unwrap()
            .contains("Method does not exist")
    );
    assert_eq!(greeted["target"], "Greeted");
    assert_eq!(greeted["arguments"][0], format!("{}: hi", client.client_id));
    assert_eq!(after["result"], "still here");
}

#[tokio::test]
async fn a_hub_that_gets_another_protocol_says_so_and_closes() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let negotiated = Request::new("POST", "/skakel/v1/hub/negotiate?negotiateVersion=1")
        .bearer(&token)
        .send(&server)
        .await;
    let id = negotiated.json()["connectionToken"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut socket = open_socket(&server, &format!("/skakel/v1/hub?id={id}"), Some(&token))
        .await
        .ok()
        .unwrap();

    socket
        .send(Message::text(
            "{\"protocol\":\"messagepack\",\"version\":1}\x1e",
        ))
        .await
        .unwrap();

    let Some(Message::Text(reply)) = next_frame(&mut socket).await else {
        panic!("no reply")
    };
    assert!(reply.contains("messagepack"), "{reply}");
}

#[tokio::test]
async fn a_negotiation_can_be_used_once() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let negotiated = Request::new("POST", "/skakel/v1/hub/negotiate?negotiateVersion=1")
        .bearer(&token)
        .send(&server)
        .await;
    let id = negotiated.json()["connectionToken"]
        .as_str()
        .unwrap()
        .to_owned();

    assert!(
        open_socket(&server, &format!("/skakel/v1/hub?id={id}"), Some(&token))
            .await
            .is_ok()
    );
    let again = open_socket(&server, &format!("/skakel/v1/hub?id={id}"), Some(&token))
        .await
        .err()
        .unwrap();

    assert_eq!(again.status, 404);
}

#[tokio::test]
async fn the_hub_takes_the_token_from_the_query_string_as_signalr_does_for_websockets() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let negotiated = Request::new(
        "POST",
        &format!("/skakel/v1/hub/negotiate?negotiateVersion=1&access_token={token}"),
    )
    .send(&server)
    .await;
    assert_eq!(negotiated.status, 200);
    let id = negotiated.json()["connectionToken"]
        .as_str()
        .unwrap()
        .to_owned();

    let socket = open_socket(
        &server,
        &format!("/skakel/v1/hub?id={id}&access_token={token}"),
        None,
    )
    .await;

    assert!(socket.is_ok());
}

#[tokio::test]
async fn a_revoked_client_is_told_why_and_disconnected_and_cannot_connect_again() {
    let server = start().await;
    let (client, token) = client_with_token(&server, "bench-1").await;
    let mut hub = hub_connect(&server, &token).await;
    hub.next_message().await;
    assert_eq!(server.open_sessions(&client.client_id), 1);

    server.clients().revoke(&client.client_id).await.unwrap();

    let closing = hub.next_non_ping().await.unwrap();
    assert_eq!(closing["target"], "SkakelClosing");
    assert_eq!(closing["arguments"][0], json!({ "reason": "revoked" }));
    assert_eq!(hub.next_non_ping().await.unwrap()["type"], 7);
    let negotiate = Request::new("POST", "/skakel/v1/hub/negotiate?negotiateVersion=1")
        .bearer(&token)
        .send(&server)
        .await;
    assert_eq!(negotiate.status, 401);
}

#[tokio::test]
async fn a_rotated_secret_ends_the_hub_with_rotated() {
    let server = start().await;
    let (client, token) = client_with_token(&server, "bench-1").await;
    let mut hub = hub_connect(&server, &token).await;
    hub.next_message().await;

    server
        .clients()
        .rotate_secret(&client.client_id)
        .await
        .unwrap();

    assert_eq!(
        hub.next_non_ping().await.unwrap()["arguments"][0],
        json!({ "reason": "rotated" })
    );
}

#[tokio::test]
async fn stopping_the_server_tells_hub_connections_and_streams_it_is_stopping() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let mut hub = hub_connect(&server, &token).await;
    hub.next_message().await;
    let mut stream = open_socket(&server, "/skakel/v1/streams/echo?target=a", Some(&token))
        .await
        .ok()
        .unwrap();

    let stopping = tokio::spawn(server.shutdown());

    assert_eq!(
        hub.next_non_ping().await.unwrap()["arguments"][0],
        json!({ "reason": "stopping" })
    );
    let Some(Message::Close(Some(frame))) = next_frame(&mut stream).await else {
        panic!("no close")
    };
    assert_eq!(u16::from(frame.code), 4003);
    stopping.await.unwrap();
}

#[tokio::test]
async fn the_hub_pings_a_connected_client() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let mut hub = hub_connect(&server, &token).await;
    hub.next_message().await;

    hub.limit = Duration::from_secs(20);
    let ping = hub.next_message().await.expect("a ping within 20 seconds");

    assert_eq!(ping["type"], 6);
}

// ---- streams ----

#[tokio::test]
async fn a_stream_is_refused_before_the_upgrade_with_a_problem_a_person_can_read() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;

    let no_token = open_socket(&server, "/skakel/v1/streams/echo?target=a", None)
        .await
        .err()
        .unwrap();
    let bad_token = open_socket(&server, "/skakel/v1/streams/echo?target=a", Some("a.b.c"))
        .await
        .err()
        .unwrap();
    let unknown = open_socket(&server, "/skakel/v1/streams/nope?target=a", Some(&token))
        .await
        .err()
        .unwrap();
    let invalid = open_socket(&server, "/skakel/v1/streams/echo", Some(&token))
        .await
        .err()
        .unwrap();
    let missing = open_socket(
        &server,
        "/skakel/v1/streams/echo?target=missing",
        Some(&token),
    )
    .await
    .err()
    .unwrap();
    let busy = open_socket(&server, "/skakel/v1/streams/echo?target=busy", Some(&token))
        .await
        .err()
        .unwrap();
    let not_a_socket = Request::get("/skakel/v1/streams/echo?target=a")
        .bearer(&token)
        .send(&server)
        .await;

    assert_eq!(no_token.status, 401);
    assert!(
        String::from_utf8_lossy(&no_token.body)
            .contains("Open streams over HTTPS with a current token.")
    );
    assert_eq!(bad_token.status, 401);
    assert_eq!(
        (unknown.status, unknown.detail()),
        (404, "This server has no stream type 'nope'.".to_owned())
    );
    assert_eq!(
        (invalid.status, invalid.detail()),
        (422, "Say which target, as ?target=<name>.".to_owned())
    );
    assert_eq!(
        (missing.status, missing.detail()),
        (404, "There is no target called missing.".to_owned())
    );
    assert_eq!(
        (busy.status, busy.detail()),
        (409, "bench-2 holds busy.".to_owned())
    );
    assert_eq!(not_a_socket.status, 400);
    assert_eq!(
        not_a_socket.header("content-type"),
        Some("application/problem+json")
    );
    assert_eq!(
        unknown.header("content-type"),
        Some("application/problem+json")
    );
}

#[tokio::test]
async fn a_stream_carries_binary_and_text_frames_in_order_and_closes_normally() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let mut stream = open_socket(
        &server,
        "/skakel/v1/streams/echo?target=a%20b",
        Some(&token),
    )
    .await
    .ok()
    .unwrap();

    stream
        .send(Message::binary(b"ping".to_vec()))
        .await
        .unwrap();
    stream.send(Message::text("{\"op\":\"x\"}")).await.unwrap();
    stream
        .send(Message::binary(b"pong".to_vec()))
        .await
        .unwrap();

    assert_eq!(
        next_frame(&mut stream).await,
        Some(Message::binary(b"ping".to_vec()))
    );
    assert_eq!(
        next_frame(&mut stream).await,
        Some(Message::text("{\"op\":\"x\"}"))
    );
    assert_eq!(
        next_frame(&mut stream).await,
        Some(Message::binary(b"pong".to_vec()))
    );
    stream.close(None).await.unwrap();
}

#[tokio::test]
async fn a_large_amount_of_data_comes_back_whole_through_the_queues() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let stream = open_socket(&server, "/skakel/v1/streams/echo?target=a", Some(&token))
        .await
        .ok()
        .unwrap();
    let chunk: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    use futures_util::StreamExt;
    let (mut sink, mut source) = stream.split();
    let sender = tokio::spawn({
        let chunk = chunk.clone();
        async move {
            for _ in 0..100 {
                sink.send(Message::binary(chunk.clone())).await.unwrap();
            }
            sink
        }
    });

    let mut received = 0usize;
    while received < chunk.len() * 100 {
        let Some(Ok(Message::Binary(data))) =
            tokio::time::timeout(Duration::from_secs(20), source.next())
                .await
                .unwrap()
        else {
            panic!("the stream ended early after {received} bytes");
        };
        assert_eq!(&data[..], &chunk[..], "a frame arrives whole and in order");
        received += data.len();
    }
    let _sink = sender.await.unwrap();
}

#[tokio::test]
async fn a_target_that_goes_away_closes_with_4004() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let mut stream = open_socket(
        &server,
        "/skakel/v1/streams/echo?target=vanish",
        Some(&token),
    )
    .await
    .ok()
    .unwrap();

    let Some(Message::Close(Some(frame))) = next_frame(&mut stream).await else {
        panic!("no close")
    };

    assert_eq!(
        (u16::from(frame.code), frame.reason.to_string()),
        (4004, "unplugged".to_owned())
    );
}

#[tokio::test]
async fn revoking_and_rotating_close_streams_with_4001_and_4002() {
    let server = start().await;
    let (revoked, token) = client_with_token(&server, "bench-1").await;
    let (rotated, token2) = client_with_token(&server, "bench-2").await;
    let mut a = open_socket(&server, "/skakel/v1/streams/echo?target=a", Some(&token))
        .await
        .ok()
        .unwrap();
    let mut b = open_socket(&server, "/skakel/v1/streams/echo?target=a", Some(&token2))
        .await
        .ok()
        .unwrap();

    server.clients().revoke(&revoked.client_id).await.unwrap();
    server
        .clients()
        .rotate_secret(&rotated.client_id)
        .await
        .unwrap();

    let Some(Message::Close(Some(a_close))) = next_frame(&mut a).await else {
        panic!("no close")
    };
    let Some(Message::Close(Some(b_close))) = next_frame(&mut b).await else {
        panic!("no close")
    };
    assert_eq!(u16::from(a_close.code), 4001);
    assert_eq!(u16::from(b_close.code), 4002);
}

#[tokio::test]
async fn the_server_pings_a_stream() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let mut stream = open_socket(&server, "/skakel/v1/streams/echo?target=a", Some(&token))
        .await
        .ok()
        .unwrap();

    // tungstenite answers the server's ping by itself; the frame comes up to the reader.
    let frame = tokio::time::timeout(
        Duration::from_secs(20),
        futures_util::StreamExt::next(&mut stream),
    )
    .await;

    assert!(matches!(
        frame.expect("a ping within 20 seconds"),
        Some(Ok(Message::Ping(_)))
    ));
}

#[tokio::test]
async fn the_serial_stream_type_speaks_the_wire_format_of_skakel_serial() {
    use skakel_serial::{ClientMessage, ServerMessage};
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let mut stream = open_socket(&server, "/skakel/v1/streams/serial?port=COM1", Some(&token))
        .await
        .ok()
        .unwrap();

    let Some(Message::Text(opened)) = next_frame(&mut stream).await else {
        panic!("no opened")
    };
    assert!(matches!(
        ServerMessage::parse(&opened),
        Some(ServerMessage::Opened { .. })
    ));
    stream
        .send(Message::text(
            ClientMessage::ModemLines {
                dtr: Some(true),
                rts: None,
            }
            .to_json(),
        ))
        .await
        .unwrap();
    let Some(Message::Text(status)) = next_frame(&mut stream).await else {
        panic!("no status")
    };
    assert!(
        matches!(ServerMessage::parse(&status), Some(ServerMessage::ModemStatus(s)) if s.dsr && s.dcd)
    );

    let busy = open_socket(&server, "/skakel/v1/streams/serial?port=busy", Some(&token))
        .await
        .err()
        .unwrap();
    assert_eq!(busy.status, 409);
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
        .keys()
        .prepare_next_certificate()
        .await
        .unwrap()
        .unwrap();

    assert!(
        fingerprints::are_equal(&presented_fingerprint(server.local_addr()).await, &current),
        "still the current one"
    );
    assert_ne!(next, current);
    let switched = server.keys().switch_certificate().await.unwrap().unwrap();
    assert!(fingerprints::are_equal(
        &presented_fingerprint(server.local_addr()).await,
        &next
    ));
    assert_eq!(switched.from, current);
}

#[tokio::test]
async fn a_hub_client_hears_the_handover_and_its_acknowledgement_is_recorded() {
    let server = start().await;
    let (client, token) = client_with_token(&server, "bench-1").await;
    let mut hub = hub_connect(&server, &token).await;
    hub.next_message().await;

    let next = server
        .keys()
        .prepare_next_certificate()
        .await
        .unwrap()
        .unwrap();

    let told = hub.next_non_ping().await.unwrap();
    assert_eq!(told["target"], "SkakelCertificates");
    assert_eq!(told["arguments"][0]["nextFingerprint"], next.as_str());
    hub.send(json!({ "type": 1, "target": "SkakelNextCertificateReceived", "arguments": [next] }))
        .await;
    let mut tries = 0;
    while !server.clients().all()[0].has_next_certificate {
        tokio::time::sleep(Duration::from_millis(20)).await;
        tries += 1;
        assert!(tries < 250, "the acknowledgement never arrived");
    }
    server.keys().switch_certificate().await.unwrap();
    let switched = hub.next_non_ping().await.unwrap();
    assert_eq!(switched["arguments"][0]["fingerprint"], next.as_str());
    assert_eq!(switched["arguments"][0]["nextFingerprint"], Value::Null);
    let _ = client;
}

#[tokio::test]
async fn an_acknowledgement_of_the_wrong_certificate_is_not_recorded() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let mut hub = hub_connect(&server, &token).await;
    hub.next_message().await;
    server.keys().prepare_next_certificate().await.unwrap();
    hub.next_non_ping().await;

    let done = hub
        .invoke("1", "SkakelNextCertificateReceived", json!(["AA:BB"]))
        .await;

    assert!(done.get("error").is_none());
    assert!(!server.clients().all()[0].has_next_certificate);
}

#[tokio::test]
async fn a_cancelled_handover_is_told_to_clients_with_no_next_fingerprint() {
    let server = start().await;
    let (_, token) = client_with_token(&server, "bench-1").await;
    let mut hub = hub_connect(&server, &token).await;
    hub.next_message().await;
    server.keys().prepare_next_certificate().await.unwrap();
    hub.next_non_ping().await;

    server.keys().cancel_next_certificate().await.unwrap();

    assert_eq!(
        hub.next_non_ping().await.unwrap()["arguments"][0]["nextFingerprint"],
        Value::Null
    );
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
