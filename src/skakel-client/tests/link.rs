//! A link against a real server: connecting, the app's own gRPC calls over the control channel's
//! connection, HTTPS requests, and every way it fails.

mod common;

use std::time::Duration;

use common::greeter::{self, GreetRequest, WatchRequest};
use common::{Recorder, free_tcp, within};
use skakel_client::{
    ClientOptions, Credentials, FailureKind, Link, LinkState, LinkStatus, Method, Pins, Url,
};
use tonic::{Code, Request};

fn record_status(link: &Link) -> Recorder<LinkStatus> {
    common::record_status(link)
}

fn states(statuses: &Recorder<LinkStatus>) -> Vec<LinkState> {
    statuses.seen().into_iter().map(|s| s.state).collect()
}

async fn linked(bench: &mut common::Bench, server: &common::Server) -> (Link, Credentials) {
    let credentials = bench.register(server).await;
    let link = Link::new(
        &server.address(),
        server.pins(),
        credentials.clone(),
        ClientOptions::default(),
    )
    .unwrap();
    (link, credentials)
}

fn greeting(text: &str) -> Request<GreetRequest> {
    Request::new(GreetRequest { text: text.into() })
}

#[tokio::test]
async fn start_connects_the_control_channel() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, credentials) = linked(&mut bench, &server).await;
    let statuses = record_status(&link);

    link.start();

    statuses.wait(|s| s.state == LinkState::Connected).await;
    assert_eq!(
        states(&statuses),
        [LinkState::Connecting, LinkState::Connected]
    );
    let hello = link.hello().await.unwrap();
    assert_eq!(hello.server, "bench");
    assert_eq!(hello.client_id, credentials.client_id);
    link.stop().await;
}

#[tokio::test]
async fn the_apps_own_service_runs_over_the_links_channel_with_its_token() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, credentials) = linked(&mut bench, &server).await;
    let statuses = record_status(&link);
    link.start();
    statuses.wait(|s| s.state == LinkState::Connected).await;

    let reply = greeter::greet(link.channel(), greeting("hello"))
        .await
        .unwrap();
    let mut events = greeter::watch(link.channel(), Request::new(WatchRequest {}))
        .await
        .unwrap();

    assert_eq!(reply.text, format!("{}: hello", credentials.client_id));
    assert_eq!(
        events.message().await.unwrap().unwrap().text,
        format!("watching for {}", credentials.client_id)
    );
    link.stop().await;
}

#[tokio::test]
async fn an_app_call_the_server_does_not_serve_is_unimplemented() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;
    let statuses = record_status(&link);
    link.start();
    statuses.wait(|s| s.state == LinkState::Connected).await;

    let mut grpc = tonic::client::Grpc::new(link.channel());
    grpc.ready().await.unwrap();
    let error = grpc
        .unary(
            greeting("hello"),
            tonic::codegen::http::uri::PathAndQuery::from_static(
                "/test.app.v1.Greeter/NoSuchMethod",
            ),
            tonic_prost::ProstCodec::<GreetRequest, greeter::GreetReply>::default(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.code(), Code::Unimplemented);
    link.stop().await;
}

#[tokio::test]
async fn an_app_call_that_is_dropped_ends_on_the_server() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, credentials) = linked(&mut bench, &server).await;
    let statuses = record_status(&link);
    link.start();
    statuses.wait(|s| s.state == LinkState::Connected).await;
    let mut events = greeter::watch(link.channel(), Request::new(WatchRequest {}))
        .await
        .unwrap();
    events.message().await.unwrap();
    // The control call and the app's call.
    assert_eq!(bench.open_sessions(&server, &credentials.client_id), 2);

    drop(events);

    within(Duration::from_secs(10), async {
        while bench.open_sessions(&server, &credentials.client_id) != 1 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    link.stop().await;
}

#[tokio::test]
async fn the_channel_is_unavailable_before_the_link_is_connected() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;

    let error = greeter::greet(link.channel(), greeting("x"))
        .await
        .unwrap_err();

    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(error.message(), "Not connected to the server.");
}

/// Longer than the pause before a link tries again after a failure, which starts at a second.
const LONGER_THAN_A_RETRY: Duration = Duration::from_millis(2500);

#[tokio::test]
async fn a_wrong_secret_is_rejected_credentials_and_closes_the_link_for_good() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let credentials = bench.register(&server).await;
    let link = Link::new(
        &server.address(),
        server.pins(),
        Credentials::new(credentials.client_id.clone(), "wrong"),
        ClientOptions::default(),
    )
    .unwrap();
    let statuses = record_status(&link);

    link.start();

    let closed = statuses.wait(|s| s.state == LinkState::Closed).await;
    let failure = closed.failure.unwrap();
    assert_eq!(failure.kind(), FailureKind::RejectedCredentials);
    assert_eq!(
        failure.message(),
        "The server refused this client's ID or secret. Pair with the server again."
    );
    tokio::time::sleep(LONGER_THAN_A_RETRY).await;
    assert_eq!(
        states(&statuses),
        [LinkState::Connecting, LinkState::Closed],
        "the link tried again"
    );
    assert_eq!(
        link.hello().await.unwrap_err().kind(),
        FailureKind::RejectedCredentials
    );
    link.stop().await;
}

#[tokio::test]
async fn a_client_revoked_while_the_link_was_down_is_closed_for_good_when_it_comes_back() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, credentials) = linked(&mut bench, &server).await;
    let statuses = record_status(&link);
    link.start();
    statuses.wait(|s| s.state == LinkState::Connected).await;
    link.stop().await;
    assert!(bench.revoke(&server, &credentials.client_id).await);

    link.start();

    let closed = statuses.wait(|s| s.state == LinkState::Closed).await;
    assert_eq!(
        closed.failure.unwrap().kind(),
        FailureKind::RejectedCredentials
    );
    tokio::time::sleep(LONGER_THAN_A_RETRY).await;
    assert_eq!(
        states(&statuses),
        [
            LinkState::Connecting,
            LinkState::Connected,
            LinkState::Stopped,
            LinkState::Connecting,
            LinkState::Closed,
        ],
        "the link tried again"
    );
    link.stop().await;
}

#[tokio::test]
async fn another_certificate_is_a_mismatch() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let credentials = bench.register(&server).await;
    let link = Link::new(
        &server.address(),
        Pins::new(&vec!["0F"; 32].join(":")).unwrap(),
        credentials,
        ClientOptions::default(),
    )
    .unwrap();
    let statuses = record_status(&link);

    link.start();

    let failed = statuses.wait(|s| s.state == LinkState::Failed).await;
    assert_eq!(
        failed.failure.unwrap().kind(),
        FailureKind::CertificateMismatch
    );
    link.stop().await;
}

#[tokio::test]
async fn a_closed_port_is_unreachable() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let credentials = bench.register(&server).await;
    let link = Link::new(
        &Url::parse(&format!("https://127.0.0.1:{}", free_tcp())).unwrap(),
        server.pins(),
        credentials,
        ClientOptions::default(),
    )
    .unwrap();

    let error = link.hello().await.unwrap_err();

    assert_eq!(error.kind(), FailureKind::Unreachable);
    assert_eq!(
        error.to_string(),
        "Could not reach the server. Check the address and that the server is running."
    );
}

#[tokio::test]
async fn a_server_of_another_version_is_a_version_mismatch() {
    let server = common::OtherVersion::start(&[1]).await;
    let link = Link::new(
        &server.address(),
        server.pins(),
        Credentials::new("client", "secret"),
        ClientOptions::default(),
    )
    .unwrap();
    let statuses = record_status(&link);

    link.start();

    let failure = statuses
        .wait(|s| s.state == LinkState::Failed)
        .await
        .failure
        .unwrap();
    assert_eq!(failure.kind(), FailureKind::VersionMismatch);
    assert_eq!(
        failure.message(),
        "This server speaks Skakel 1 and this app speaks Skakel 3. Update the server."
    );
    link.stop().await;
}

#[tokio::test]
async fn revoking_the_client_closes_the_link_for_good_and_ends_the_apps_calls() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, credentials) = linked(&mut bench, &server).await;
    let statuses = record_status(&link);
    link.start();
    statuses.wait(|s| s.state == LinkState::Connected).await;
    let mut events = greeter::watch(link.channel(), Request::new(WatchRequest {}))
        .await
        .unwrap();
    events.message().await.unwrap();

    assert!(bench.revoke(&server, &credentials.client_id).await);

    let ended = events.message().await.unwrap_err();
    assert_eq!(ended.code(), Code::Unauthenticated);

    let closed = statuses.wait(|s| s.state == LinkState::Closed).await;
    let failure = closed.failure.unwrap();
    assert_eq!(failure.kind(), FailureKind::Revoked);
    assert_eq!(
        failure.message(),
        "The server revoked this client. Pair with the server again."
    );
    link.stop().await;
}

#[tokio::test]
async fn rotating_the_secret_closes_the_link_for_good() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, credentials) = linked(&mut bench, &server).await;
    let statuses = record_status(&link);
    link.start();
    statuses.wait(|s| s.state == LinkState::Connected).await;

    bench.rotate(&server, &credentials.client_id).await;

    let closed = statuses.wait(|s| s.state == LinkState::Closed).await;
    assert_eq!(closed.failure.unwrap().kind(), FailureKind::Rotated);
    link.stop().await;
}

#[tokio::test]
async fn a_server_that_ends_every_connection_is_connected_to_again() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;
    let statuses = record_status(&link);
    link.start();
    statuses.wait(|s| s.state == LinkState::Connected).await;

    bench.end_all(&server).await;

    let failed = statuses.wait(|s| s.state == LinkState::Failed).await;
    assert_eq!(failed.failure.unwrap().kind(), FailureKind::ServerStopping);
    statuses
        .wait_count(2, |s| s.state == LinkState::Connected)
        .await;
    assert_eq!(link.status().state, LinkState::Connected);
    link.stop().await;
}

#[tokio::test]
async fn stop_closes_the_control_channel_and_says_so() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;
    let statuses = record_status(&link);
    link.start();
    statuses.wait(|s| s.state == LinkState::Connected).await;

    link.stop().await;

    assert_eq!(link.status().state, LinkState::Stopped);
    statuses.wait(|s| s.state == LinkState::Stopped).await;
    // And the connection is not there for a call.
    let error = greeter::greet(link.channel(), greeting("x"))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
}

#[tokio::test]
async fn a_link_that_closed_for_good_starts_again_when_asked() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let credentials = bench.register(&server).await;
    let link = Link::new(
        &server.address(),
        server.pins(),
        Credentials::new(credentials.client_id.clone(), "wrong"),
        ClientOptions::default(),
    )
    .unwrap();
    let statuses = record_status(&link);
    link.start();
    statuses.wait(|s| s.state == LinkState::Closed).await;

    link.start();

    statuses
        .wait_count(2, |s| s.state == LinkState::Closed)
        .await;
    assert_eq!(
        states(&statuses),
        [
            LinkState::Connecting,
            LinkState::Closed,
            LinkState::Connecting,
            LinkState::Closed
        ],
        "the second start ran"
    );
    link.stop().await;
}

#[tokio::test]
async fn a_link_that_was_stopped_can_start_again() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;
    let statuses = record_status(&link);
    link.start();
    statuses.wait(|s| s.state == LinkState::Connected).await;
    link.stop().await;

    link.start();

    within(Duration::from_secs(20), async {
        while link.status().state != LinkState::Connected {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        greeter::greet(link.channel(), greeting("again"))
            .await
            .unwrap()
            .text
            .ends_with(": again")
    );
    link.stop().await;
}

#[tokio::test]
async fn request_sends_the_token_over_the_pinned_connection() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, credentials) = linked(&mut bench, &server).await;

    let response = link
        .request(Method::GET, "/app/whoami", |r| r)
        .await
        .unwrap();

    assert!(response.status().is_success());
    assert_eq!(response.text(), credentials.client_id);
}

#[tokio::test]
async fn request_refuses_a_path_that_would_leave_the_server_with_an_error_not_a_panic() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;

    for path in [
        "//evil.example/x",
        "/\t/evil.example/x",
        "/\n/evil.example",
        "/\\evil.example",
        "evil",
        "",
    ] {
        let error = link.request(Method::GET, path, |r| r).await.unwrap_err();
        assert_eq!(error.kind(), FailureKind::InvalidRequest, "{path:?}");
    }
}

#[tokio::test]
async fn a_token_is_taken_once_and_reused() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;

    let first = link.access_token().await.unwrap();
    let second = link.access_token().await.unwrap();
    link.hello().await.unwrap();

    assert_eq!(first, second);
    assert_eq!(
        link.access_token().await.unwrap(),
        first,
        "the hello did not take another"
    );
}
