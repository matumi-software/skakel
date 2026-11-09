//! Tokens renewed before they run out, the hub renewed with them unseen, and the certificate
//! handover, against a real server.

mod common;

use std::time::Duration;

use common::{ManualClock, Recorder, within};
use serde_json::json;
use skakel_client::{ClientOptions, Credentials, FailureKind, Link, LinkState, LinkStatus, Pins};

fn record_status(link: &Link) -> Recorder<LinkStatus> {
    let recorder = Recorder::new();
    let to = recorder.clone();
    link.on_status_changed(move |status| {
        let to = to.clone();
        async move { to.record(status) }
    });
    recorder
}

fn record_pins(link: &Link) -> Recorder<Pins> {
    let recorder = Recorder::new();
    let to = recorder.clone();
    link.on_pins_changed(move |pins| {
        let to = to.clone();
        async move {
            to.record(pins);
            Ok::<(), std::convert::Infallible>(())
        }
    });
    recorder
}

async fn connected(link: &Link, statuses: &Recorder<LinkStatus>) {
    link.start();
    statuses.wait(|s| s.state == LinkState::Connected).await;
    // The server handles the connection once its own setup is done; a call that came back has been
    // through that.
    link.invoke("Echo", vec![json!("x")]).await.unwrap();
}

async fn link_with(
    bench: &mut common::Bench,
    server: &common::Server,
    options: ClientOptions,
) -> (Link, Credentials) {
    let credentials = bench.register(server).await;
    let link = Link::new(
        &server.address(),
        server.pins(),
        credentials.clone(),
        options,
    )
    .unwrap();
    (link, credentials)
}

#[tokio::test]
async fn a_token_is_reused_until_a_minute_before_it_runs_out() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let clock = ManualClock::new();
    let (link, _) = link_with(
        &mut bench,
        &server,
        ClientOptions {
            clock: clock.clone(),
            ..ClientOptions::default()
        },
    )
    .await;
    let first = link.access_token().await.unwrap();

    // Two minutes before the end it is still reused.
    clock.advance(Duration::from_secs(28 * 60));
    assert_eq!(link.access_token().await.unwrap(), first);

    // Half a minute before the end it is not.
    clock.advance(Duration::from_secs(90));
    let renewed = link.access_token().await.unwrap();

    assert_ne!(renewed, first);
}

#[tokio::test]
async fn the_hub_connects_again_with_a_fresh_token_before_it_runs_out_without_saying_so() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let clock = ManualClock::new();
    let (link, _) = link_with(
        &mut bench,
        &server,
        ClientOptions {
            clock: clock.clone(),
            ..ClientOptions::default()
        },
    )
    .await;
    let statuses = record_status(&link);
    connected(&link, &statuses).await;
    let connection: String = link.invoke_as("Connection", vec![]).await.unwrap();
    let token = link.access_token().await.unwrap();
    clock.when_sleeping(1).await;

    clock.advance(Duration::from_secs(29 * 60 + 31));

    let renewed = within(Duration::from_secs(20), async {
        loop {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let now: String = link.invoke_as("Connection", vec![]).await.unwrap();
            if now != connection {
                return now;
            }
        }
    })
    .await;
    assert_ne!(renewed, connection);
    assert_ne!(
        link.access_token().await.unwrap(),
        token,
        "the new connection took a fresh token"
    );
    let states: Vec<LinkState> = statuses.seen().into_iter().map(|s| s.state).collect();
    assert_eq!(
        states,
        [LinkState::Connecting, LinkState::Connected],
        "a renewal is not a change anyone hears of"
    );
    link.stop().await;
}

async fn acknowledged(bench: &mut common::Bench, server: &common::Server, client: &str) {
    within(Duration::from_secs(15), async {
        loop {
            if bench
                .clients(server)
                .await
                .iter()
                .any(|c| c.0 == client && c.2)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
}

#[tokio::test]
async fn a_handover_is_learned_over_the_hub_saved_by_the_app_and_acknowledged() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, credentials) = link_with(&mut bench, &server, ClientOptions::default()).await;
    let pins = record_pins(&link);
    let statuses = record_status(&link);
    connected(&link, &statuses).await;
    let current = server.fingerprint.clone();

    let next = bench.prepare(&server).await;

    let learned = pins
        .wait(|p| {
            p.next_fingerprint()
                .is_some_and(|n| Pins::new(&next).unwrap().trusts(n))
        })
        .await;
    assert!(learned.trusts(&current) && Pins::new(&current).unwrap().trusts(learned.fingerprint()));
    acknowledged(&mut bench, &server, &credentials.client_id).await;

    let switched = bench.switch(&server).await;
    assert!(switched.not_received.is_empty(), "{switched:?}");

    pins.wait(|p| p.next_fingerprint().is_none() && p.trusts(&next) && !p.trusts(&current))
        .await;
    assert_eq!(link.pins(), Pins::new(&next).unwrap());

    // New connections get the new certificate: the learned pins reach it, the old pin alone does not.
    let learned_link = Link::new(
        &server.address(),
        link.pins(),
        credentials.clone(),
        ClientOptions::default(),
    )
    .unwrap();
    assert_eq!(
        learned_link.hello().await.unwrap().client_id,
        credentials.client_id
    );
    let stale = Link::new(
        &server.address(),
        Pins::new(&current).unwrap(),
        credentials,
        ClientOptions::default(),
    )
    .unwrap();
    assert_eq!(
        stale.hello().await.unwrap_err().kind(),
        FailureKind::CertificateMismatch
    );

    // And the link itself connects again across the switch.
    link.stop().await;
    let again = record_status(&link);
    link.start();
    again.wait(|s| s.state == LinkState::Connected).await;
    link.stop().await;
}

#[tokio::test]
async fn a_cancelled_handover_is_forgotten() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = link_with(&mut bench, &server, ClientOptions::default()).await;
    let pins = record_pins(&link);
    let statuses = record_status(&link);
    connected(&link, &statuses).await;
    bench.prepare(&server).await;
    pins.wait(|p| p.next_fingerprint().is_some()).await;

    bench.cancel(&server).await;

    pins.wait(|p| p.next_fingerprint().is_none()).await;
    assert_eq!(link.pins(), server.pins());
    link.stop().await;
}

#[tokio::test]
async fn a_handover_the_app_could_not_save_is_not_acknowledged() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, credentials) = link_with(&mut bench, &server, ClientOptions::default()).await;
    let tried: Recorder<()> = Recorder::new();
    let to = tried.clone();
    link.on_pins_changed(move |_| {
        let to = to.clone();
        async move {
            to.record(());
            Err::<(), _>(std::io::Error::other("disk full"))
        }
    });
    let statuses = record_status(&link);
    connected(&link, &statuses).await;

    bench.prepare(&server).await;
    tried.wait(|_| true).await;
    // A call after the handler: the hub runs a connection's messages in order, so an
    // acknowledgement would be in by now.
    link.invoke("Echo", vec![json!("x")]).await.unwrap();

    let clients = bench.clients(&server).await;
    assert!(
        !clients
            .iter()
            .find(|c| c.0 == credentials.client_id)
            .unwrap()
            .2
    );
    link.stop().await;
}
