//! The pairing window: a server takes new pairing requests only while the app has opened one, and
//! refuses the rest with 403 and the reason `pairing-closed`. The window's expiry under a paused
//! clock is tested in the crate's own unit tests, where no real sockets are involved.

mod common;

use std::time::Duration;

use common::*;
use serde_json::{Value, json};
use skakel_server::{Approval, MAX_PAIRING_WINDOW, MIN_PAIRING_WINDOW, ServerEvent, SkakelServer};
use skakel_wire::pairing::{commit, compute, new_nonce};

async fn closed_server() -> SkakelServer {
    closed_builder().start().await.expect("the server starts")
}

async fn open(server: &SkakelServer, name: &str) -> (Reply, String) {
    let nonce = new_nonce().unwrap();
    let reply = Request::new("POST", &format!("{}/pair", skakel_wire::BASE_PATH))
        .json(&json!({ "clientName": name, "commitment": commit(&nonce) }))
        .send(server)
        .await;
    (reply, nonce)
}

async fn reveal(server: &SkakelServer, opened: &Value, nonce: &str) -> Reply {
    Request::new(
        "POST",
        &format!(
            "{}/pair/{}/reveal",
            skakel_wire::BASE_PATH,
            opened["requestId"].as_str().unwrap()
        ),
    )
    .json(&json!({ "clientNonce": nonce }))
    .send(server)
    .await
}

fn assert_closed(reply: &Reply) {
    assert_eq!(reply.status, 403, "{}", reply.text());
    assert_eq!(reply.json()["reason"], "pairing-closed");
    assert!(
        reply.detail().contains("not taking pairing requests"),
        "{}",
        reply.detail()
    );
}

#[tokio::test]
async fn a_server_takes_no_pairing_request_until_the_app_opens_a_window() {
    let server = closed_server().await;

    let (reply, _) = open(&server, "lab pc").await;

    assert_closed(&reply);
    assert!(!server.pairing_window().open);
}

#[tokio::test]
async fn a_refusal_outside_the_window_reads_no_body() {
    let server = closed_server().await;

    let reply = Request::new("POST", &format!("{}/pair", skakel_wire::BASE_PATH))
        .form("this is not json")
        .send(&server)
        .await;

    assert_closed(&reply);
}

#[tokio::test]
async fn an_open_window_takes_requests_and_closing_it_refuses_new_ones_but_not_those_open() {
    let server = closed_server().await;
    server.open_pairing(Duration::from_secs(600));
    let window = server.pairing_window();
    assert!(window.open && !window.always_open);
    assert!(window.remaining.unwrap() > Duration::from_secs(590));

    let (opened, nonce) = open(&server, "lab pc").await;
    assert_eq!(opened.status, 200, "{}", opened.text());
    let opened = opened.json();
    server.close_pairing();

    assert!(!server.pairing_window().open);
    let (refused, _) = open(&server, "other pc").await;
    assert_closed(&refused);
    // The request that was open goes on: reveal, approve and the credentials still work.
    assert_eq!(reveal(&server, &opened, &nonce).await.status, 204);
    let overview = server.pairing().overview().await;
    let code = compute(
        &server.fingerprint(),
        "lab pc",
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
}

#[tokio::test]
async fn refusals_outside_the_window_spend_none_of_the_pairing_budget() {
    let server = closed_server().await;
    // More refusals than the five opens an address may make in a window. If they counted, the
    // address could open nothing afterwards.
    for _ in 0..8 {
        let (reply, _) = open(&server, "lab pc").await;
        assert_closed(&reply);
    }

    server.open_pairing(Duration::from_secs(600));

    // An address may have three requests open at once.
    for i in 0..3 {
        let (reply, _) = open(&server, "lab pc").await;
        assert_eq!(reply.status, 200, "open {i}: {}", reply.text());
    }
}

#[tokio::test]
async fn a_server_built_to_take_requests_always_has_no_window_to_close() {
    let server = closed_builder()
        .pairing_always_open()
        .start()
        .await
        .expect("the server starts");

    assert!(server.pairing_window().open);
    assert!(server.pairing_window().always_open);
    assert_eq!(server.pairing_window().remaining, None);
    server.close_pairing();
    let (reply, _) = open(&server, "lab pc").await;
    assert_eq!(reply.status, 200, "{}", reply.text());
}

#[tokio::test]
async fn the_app_hears_when_the_window_opens_and_closes() {
    let server = closed_server().await;
    let mut events = server.subscribe();

    server.open_pairing(Duration::from_secs(600));
    server.close_pairing();
    // Closing a window that is closed says nothing more.
    server.close_pairing();

    let opened = events.try_recv();
    let closed = events.try_recv();
    assert!(
        matches!(&opened, Some(ServerEvent::PairingWindow(w)) if w.open && w.remaining.is_some()),
        "{opened:?}"
    );
    assert!(
        matches!(&closed, Some(ServerEvent::PairingWindow(w)) if !w.open && w.remaining.is_none()),
        "{closed:?}"
    );
    assert!(events.try_recv().is_none());
}

#[tokio::test]
async fn the_length_of_a_window_is_held_between_a_minute_and_an_hour() {
    let server = closed_server().await;

    server.open_pairing(Duration::from_secs(1));
    let shortest = server.pairing_window().remaining.unwrap();
    server.open_pairing(Duration::from_secs(10 * 60 * 60));
    let longest = server.pairing_window().remaining.unwrap();

    assert!(
        shortest > MIN_PAIRING_WINDOW - Duration::from_secs(5),
        "{shortest:?}"
    );
    assert!(shortest <= MIN_PAIRING_WINDOW);
    assert!(
        longest > MAX_PAIRING_WINDOW - Duration::from_secs(5),
        "{longest:?}"
    );
    assert!(longest <= MAX_PAIRING_WINDOW);
}
