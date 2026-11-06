//! A link against a real .NET server: connecting, the app's own hub messages, requests, and every
//! way it fails.

mod common;

use std::time::Duration;

use common::{Recorder, free_tcp, within};
use serde_json::json;
use skakel_client::{
    ClientOptions, Credentials, FailureKind, InvokeError, Link, LinkState, LinkStatus, Method,
    Pins, Url,
};

pub fn record_status(link: &Link) -> Recorder<LinkStatus> {
    let recorder = Recorder::new();
    let to = recorder.clone();
    link.on_status_changed(move |status| {
        let to = to.clone();
        async move { to.record(status) }
    });
    recorder
}

fn states(statuses: &Recorder<LinkStatus>) -> Vec<LinkState> {
    statuses.seen().into_iter().map(|s| s.state).collect()
}

async fn linked(dotnet: &mut common::Dotnet, server: &common::Server) -> (Link, Credentials) {
    let credentials = dotnet.register(server).await;
    let link = Link::new(
        &server.address(),
        server.pins(),
        credentials.clone(),
        ClientOptions::default(),
    )
    .unwrap();
    (link, credentials)
}

#[tokio::test]
async fn start_connects_the_hub() {
    let mut dotnet = dotnet!();
    let server = dotnet.server().await;
    let (link, credentials) = linked(&mut dotnet, &server).await;
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
async fn on_and_invoke_carry_the_apps_own_messages() {
    let mut dotnet = dotnet!();
    let server = dotnet.server().await;
    let (link, credentials) = linked(&mut dotnet, &server).await;
    let greetings: Recorder<String> = Recorder::new();
    let to = greetings.clone();
    let _handling = link.on("Greeted", move |arguments| {
        let to = to.clone();
        async move { to.record(arguments[0].as_str().unwrap().to_owned()) }
    });
    let statuses = record_status(&link);
    link.start();
    statuses.wait(|s| s.state == LinkState::Connected).await;

    assert_eq!(
        link.invoke("Greet", vec![json!("hello")]).await.unwrap(),
        json!(null)
    );

    assert_eq!(
        greetings.wait(|_| true).await,
        format!("{}: hello", credentials.client_id)
    );
    assert_eq!(
        link.invoke("Echo", vec![json!("echo")]).await.unwrap(),
        json!("echo")
    );
    assert_eq!(
        link.invoke_as::<String>("Echo", vec![json!("typed")])
            .await
            .unwrap(),
        "typed"
    );
    link.send("Greet", vec![json!("sent")]).await.unwrap();
    greetings.wait(|g| g.ends_with(": sent")).await;
    link.stop().await;
}

#[tokio::test]
async fn a_hub_method_that_does_not_exist_is_the_servers_error() {
    let mut dotnet = dotnet!();
    let server = dotnet.server().await;
    let (link, _) = linked(&mut dotnet, &server).await;
    let statuses = record_status(&link);
    link.start();
    statuses.wait(|s| s.state == LinkState::Connected).await;

    let error = link.invoke("NoSuchMethod", vec![]).await.unwrap_err();

    assert!(
        matches!(&error, InvokeError::Server(text) if text.contains("NoSuchMethod")),
        "{error:?}"
    );
    link.stop().await;
}

#[tokio::test]
async fn a_handler_that_is_dropped_stops_hearing_the_message() {
    let mut dotnet = dotnet!();
    let server = dotnet.server().await;
    let (link, _) = linked(&mut dotnet, &server).await;
    let heard: Recorder<String> = Recorder::new();
    let to = heard.clone();
    let handling = link.on("Greeted", move |arguments| {
        let to = to.clone();
        async move { to.record(arguments[0].as_str().unwrap().to_owned()) }
    });
    let statuses = record_status(&link);
    link.start();
    statuses.wait(|s| s.state == LinkState::Connected).await;
    link.invoke("Greet", vec![json!("one")]).await.unwrap();
    heard.wait(|_| true).await;

    drop(handling);
    link.invoke("Greet", vec![json!("two")]).await.unwrap();
    // The hub runs a connection's messages in order: a call after the greeting has been through.
    link.invoke("Echo", vec![json!("x")]).await.unwrap();

    assert_eq!(heard.seen().len(), 1);
    link.stop().await;
}

#[tokio::test]
#[should_panic(expected = "Skakel's own")]
async fn on_refuses_a_name_that_is_skakels_own() {
    let mut dotnet = dotnet!();
    let server = dotnet.server().await;
    let (link, _) = linked(&mut dotnet, &server).await;

    let _ = link.on("SkakelSomething", |_| async {});
}

#[tokio::test]
async fn invoke_says_not_connected_before_the_link_is() {
    let mut dotnet = dotnet!();
    let server = dotnet.server().await;
    let (link, _) = linked(&mut dotnet, &server).await;

    let error = link.invoke("Echo", vec![json!("x")]).await.unwrap_err();

    assert!(
        matches!(&error, InvokeError::Failed(e) if e.kind() == FailureKind::NotConnected),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_wrong_secret_is_rejected_credentials() {
    let mut dotnet = dotnet!();
    let server = dotnet.server().await;
    let credentials = dotnet.register(&server).await;
    let link = Link::new(
        &server.address(),
        server.pins(),
        Credentials::new(credentials.client_id, "wrong"),
        ClientOptions::default(),
    )
    .unwrap();
    let statuses = record_status(&link);

    link.start();

    let failed = statuses.wait(|s| s.state == LinkState::Failed).await;
    assert_eq!(
        failed.failure.unwrap().kind(),
        FailureKind::RejectedCredentials
    );
    assert_eq!(
        link.hello().await.unwrap_err().kind(),
        FailureKind::RejectedCredentials
    );
    link.stop().await;
}

#[tokio::test]
async fn another_certificate_is_a_mismatch() {
    let mut dotnet = dotnet!();
    let server = dotnet.server().await;
    let credentials = dotnet.register(&server).await;
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
    let mut dotnet = dotnet!();
    let server = dotnet.server().await;
    let credentials = dotnet.register(&server).await;
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
    let mut dotnet = dotnet!();
    let server = dotnet.server().await;
    dotnet.command(&format!("versions {} 2", server.id)).await;
    let (link, _) = linked(&mut dotnet, &server).await;
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
        "This server speaks Skakel 2 and this app speaks Skakel 1. Update the app."
    );
    link.stop().await;
}

#[tokio::test]
async fn revoking_the_client_closes_the_link_for_good() {
    let mut dotnet = dotnet!();
    let server = dotnet.server().await;
    let (link, credentials) = linked(&mut dotnet, &server).await;
    let statuses = record_status(&link);
    link.start();
    statuses.wait(|s| s.state == LinkState::Connected).await;

    assert_eq!(
        dotnet
            .command(&format!("revoke {} {}", server.id, credentials.client_id))
            .await,
        true
    );

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
    let mut dotnet = dotnet!();
    let server = dotnet.server().await;
    let (link, credentials) = linked(&mut dotnet, &server).await;
    let statuses = record_status(&link);
    link.start();
    statuses.wait(|s| s.state == LinkState::Connected).await;

    dotnet
        .command(&format!("rotate {} {}", server.id, credentials.client_id))
        .await;

    let closed = statuses.wait(|s| s.state == LinkState::Closed).await;
    assert_eq!(closed.failure.unwrap().kind(), FailureKind::Rotated);
    link.stop().await;
}

#[tokio::test]
async fn a_server_that_ends_every_connection_is_connected_to_again() {
    let mut dotnet = dotnet!();
    let server = dotnet.server().await;
    let (link, _) = linked(&mut dotnet, &server).await;
    let statuses = record_status(&link);
    link.start();
    statuses.wait(|s| s.state == LinkState::Connected).await;
    // The server tracks the connection once its own handling of it started; a call that came back
    // has been through that.
    link.invoke("Echo", vec![json!("x")]).await.unwrap();

    dotnet.command(&format!("end-all {}", server.id)).await;

    let failed = statuses.wait(|s| s.state == LinkState::Failed).await;
    assert_eq!(failed.failure.unwrap().kind(), FailureKind::ServerStopping);
    statuses
        .wait(|_| {
            states(&statuses)
                .iter()
                .filter(|s| **s == LinkState::Connected)
                .count()
                == 2
        })
        .await;
    assert_eq!(link.status().state, LinkState::Connected);
    link.stop().await;
}

#[tokio::test]
async fn stop_closes_the_hub_and_says_so() {
    let mut dotnet = dotnet!();
    let server = dotnet.server().await;
    let (link, _) = linked(&mut dotnet, &server).await;
    let statuses = record_status(&link);
    link.start();
    statuses.wait(|s| s.state == LinkState::Connected).await;

    link.stop().await;

    assert_eq!(link.status().state, LinkState::Stopped);
    assert_eq!(statuses.seen().last().unwrap().state, LinkState::Stopped);
    // And the hub is not there for a call.
    let error = link.invoke("Echo", vec![json!("x")]).await.unwrap_err();
    assert!(matches!(&error, InvokeError::Failed(e) if e.kind() == FailureKind::NotConnected));
}

#[tokio::test]
async fn a_link_that_was_stopped_can_start_again() {
    let mut dotnet = dotnet!();
    let server = dotnet.server().await;
    let (link, _) = linked(&mut dotnet, &server).await;
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
    assert_eq!(
        link.invoke_as::<String>("Echo", vec![json!("again")])
            .await
            .unwrap(),
        "again"
    );
    link.stop().await;
}

#[tokio::test]
async fn request_sends_the_token_over_the_pinned_connection() {
    let mut dotnet = dotnet!();
    let server = dotnet.server().await;
    let (link, credentials) = linked(&mut dotnet, &server).await;

    let response = link
        .request(Method::GET, "/skakel/v1/hello", |r| r)
        .await
        .unwrap();

    assert!(response.status().is_success());
    assert!(
        response
            .text()
            .await
            .unwrap()
            .contains(&credentials.client_id)
    );
}

#[tokio::test]
#[should_panic(expected = "path on its server")]
async fn request_refuses_a_path_that_would_leave_the_server() {
    let mut dotnet = dotnet!();
    let server = dotnet.server().await;
    let (link, _) = linked(&mut dotnet, &server).await;

    let _ = link.request(Method::GET, "//evil.example/x", |r| r).await;
}

#[tokio::test]
async fn a_token_is_taken_once_and_reused() {
    let mut dotnet = dotnet!();
    let server = dotnet.server().await;
    let (link, _) = linked(&mut dotnet, &server).await;

    let first = link.access_token().await.unwrap();
    let second = link.access_token().await.unwrap();
    link.hello().await.unwrap();

    assert_eq!(first, second);
    assert_eq!(
        dotnet.command(&format!("counts {}", server.id)).await["tokens"],
        1
    );
}
