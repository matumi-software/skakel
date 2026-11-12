//! Following a server that moved: only when nothing answers at the saved address, and only to one
//! that proves its certificate. Discovery is real where it can be, and a copied answer is made by
//! hand.

mod common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use common::{Recorder, free_tcp, free_udp};
use skakel_client::{
    Browser, BrowserOptions, ClientOptions, DiscoveredServer, FailureKind, Link, LinkEvent, LinkState,
    LinkStatus, SkakelApp, Url,
};

fn record_status(link: &Link) -> Recorder<LinkStatus> {
    common::record_status(link)
}

fn record_moves(link: &Link) -> Recorder<Url> {
    let recorder = Recorder::new();
    let to = recorder.clone();
    let mut events = link.events();
    tokio::spawn(async move {
        while let Ok(event) = events.recv().await {
            if let LinkEvent::AddressChanged(address) = event {
                to.record(address);
            }
        }
    });
    recorder
}

fn answer(port: u16, fingerprint: &str) -> DiscoveredServer {
    DiscoveredServer {
        name: "bench".into(),
        address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port,
        fingerprint: fingerprint.to_owned(),
        app: SkakelApp {
            id: "test-app".into(),
            version: "1.2.3".into(),
        },
        versions: vec![2],
        other_endpoints: Vec::new(),
    }
}

fn browser_for(targets: &[u16]) -> Browser {
    Browser::with_options(BrowserOptions {
        port: 5240,
        app_ids: Some(vec!["test-app".into()]),
        probe_targets: Some(
            targets
                .iter()
                .map(|udp| SocketAddr::from(([127, 0, 0, 1], *udp)))
                .collect(),
        ),
        probe_interval: Duration::from_millis(300),
    })
}

#[tokio::test]
async fn a_link_follows_its_server_to_another_port() {
    let mut bench = common::Bench::new();
    let (udp1, udp2, tcp2) = (free_udp(), free_udp(), free_tcp());
    let first = bench.server_in("moving", None, Some(udp1)).await;
    let credentials = bench.register(&first).await;
    let browser = browser_for(&[udp1, udp2]);
    browser.start().await.unwrap();
    let link = Link::new(
        &first.address(),
        first.pins(),
        credentials,
        ClientOptions {
            browser: Some(browser.clone()),
            ..ClientOptions::default()
        },
    )
    .unwrap();
    let statuses = record_status(&link);
    let moves = record_moves(&link);
    link.start();
    statuses.wait(|s| s.state == LinkState::Connected).await;

    bench.stop(&first).await;
    statuses
        .wait(|s| {
            s.failure
                .as_ref()
                .is_some_and(|f| f.kind() == FailureKind::Unreachable)
        })
        .await;
    let second = bench.server_in("moving", Some(tcp2), Some(udp2)).await;
    assert_eq!(
        second.fingerprint, first.fingerprint,
        "the same state is the same certificate"
    );

    assert_eq!(moves.wait(|_| true).await, second.address());
    assert_eq!(link.address(), second.address());
    statuses
        .wait_count(2, |s| s.state == LinkState::Connected)
        .await;
    link.stop().await;
    browser.stop();
}

#[tokio::test]
async fn a_link_does_not_follow_an_answer_that_copied_the_fingerprint() {
    let mut bench = common::Bench::new();
    let first = bench.server_in("real", None, None).await;
    let credentials = bench.register(&first).await;
    let decoy = bench.server_in("decoy", None, None).await;
    let browser = browser_for(&[]);
    let link = Link::new(
        &first.address(),
        first.pins(),
        credentials,
        ClientOptions {
            browser: Some(browser.clone()),
            ..ClientOptions::default()
        },
    )
    .unwrap();
    let statuses = record_status(&link);
    let moves = record_moves(&link);
    link.start();
    statuses.wait(|s| s.state == LinkState::Connected).await;
    bench.stop(&first).await;
    statuses
        .wait(|s| {
            s.failure
                .as_ref()
                .is_some_and(|f| f.kind() == FailureKind::Unreachable)
        })
        .await;

    // The decoy answers with the real server's fingerprint, and has another certificate.
    browser.add_for_test(answer(decoy.port, &first.fingerprint), 0);
    tokio::time::sleep(Duration::from_millis(500)).await;
    link.following().await;

    assert!(moves.seen().is_empty());
    assert_eq!(link.address(), first.address());
    link.stop().await;
}

#[tokio::test]
async fn a_link_follows_its_server_past_an_address_that_copied_the_fingerprint() {
    let mut bench = common::Bench::new();
    let first = bench.server_in("real", None, None).await;
    let credentials = bench.register(&first).await;
    let decoy = bench.server_in("decoy", None, None).await;
    let browser = browser_for(&[]);
    let link = Link::new(
        &first.address(),
        first.pins(),
        credentials,
        ClientOptions {
            browser: Some(browser.clone()),
            ..ClientOptions::default()
        },
    )
    .unwrap();
    let statuses = record_status(&link);
    let moves = record_moves(&link);
    link.start();
    statuses.wait(|s| s.state == LinkState::Connected).await;
    bench.stop(&first).await;
    statuses
        .wait(|s| {
            s.failure
                .as_ref()
                .is_some_and(|f| f.kind() == FailureKind::Unreachable)
        })
        .await;

    // The copy answers first, so the list shows it; the real server is still among the candidates.
    browser.add_for_test(answer(decoy.port, &first.fingerprint), 0);
    let second = bench.server_in("real", None, None).await;
    browser.add_for_test(answer(second.port, &first.fingerprint), 0);

    assert_eq!(browser.servers().len(), 1);
    assert_eq!(browser.servers()[0].port, decoy.port);
    assert_eq!(moves.wait(|_| true).await, second.address());
    link.stop().await;
}

#[tokio::test]
async fn a_link_that_is_refused_by_the_server_does_not_go_looking_for_another() {
    let mut bench = common::Bench::new();
    let server = bench.server_in("real", None, None).await;
    let other = bench.server_in("real", None, None).await;
    let credentials = bench.register(&server).await;
    let browser = browser_for(&[]);
    browser.add_for_test(answer(other.port, &server.fingerprint), 0);
    let link = Link::new(
        &server.address(),
        server.pins(),
        skakel_client::Credentials::new(credentials.client_id, "wrong"),
        ClientOptions {
            browser: Some(browser.clone()),
            ..ClientOptions::default()
        },
    )
    .unwrap();
    let statuses = record_status(&link);
    let moves = record_moves(&link);

    link.start();

    let closed = statuses.wait(|s| s.state == LinkState::Closed).await;
    assert_eq!(
        closed.failure.unwrap().kind(),
        FailureKind::RejectedCredentials
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        moves.seen().is_empty(),
        "credentials the server refused are not a reason to move"
    );
    assert_eq!(link.address(), server.address());
    link.stop().await;
}
