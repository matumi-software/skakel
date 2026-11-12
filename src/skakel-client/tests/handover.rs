//! Tokens renewed before they run out, the control call renewed with them on the same connection
//! unseen, and the certificate handover, against a real server.

mod common;

use std::time::Duration;

use common::greeter::{self, GreetRequest};
use common::{ManualClock, Recorder, within};
use skakel_client::tonic::Request;
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
}

/// The states the link went through.
fn states(statuses: &Recorder<LinkStatus>) -> Vec<LinkState> {
    statuses.seen().into_iter().map(|s| s.state).collect()
}

/// An app call through the link's channel, which goes over the control connection.
async fn greet(link: &Link) -> String {
    greeter::greet(
        link.channel(),
        Request::new(GreetRequest { text: "hi".into() }),
    )
    .await
    .unwrap()
    .text
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
async fn the_control_call_is_renewed_on_the_same_connection_before_its_token_runs_out_unseen() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let clock = ManualClock::new();
    let credentials = bench.register(&server).await;
    let proxy = common::CountingProxy::start(server.port).await;
    let link = Link::new(
        &proxy.address(),
        server.pins(),
        credentials.clone(),
        ClientOptions {
            clock: clock.clone(),
            ..ClientOptions::default()
        },
    )
    .unwrap();
    let statuses = record_status(&link);
    connected(&link, &statuses).await;
    let token = link.access_token().await.unwrap();
    clock.when_sleeping(1).await;
    let before = proxy.connections();

    clock.advance(Duration::from_secs(29 * 60 + 31));

    let renewed = within(Duration::from_secs(20), async {
        loop {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let now = link.access_token().await.unwrap();
            if now != token {
                return now;
            }
        }
    })
    .await;
    // The old call is let go once the new one has said the certificates.
    within(Duration::from_secs(20), async {
        while bench.open_sessions(&server, &credentials.client_id) != 1 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert_ne!(renewed, token);
    assert!(greet(&link).await.ends_with(": hi"));
    assert_eq!(
        proxy.connections() - before,
        1,
        "only the token request's HTTPS connection; the gRPC connection stayed"
    );
    assert_eq!(
        states(&statuses),
        [LinkState::Connecting, LinkState::Connected],
        "a renewal is not a change anyone hears of"
    );
    link.stop().await;
}

#[tokio::test]
async fn a_control_call_the_server_ends_at_its_tokens_end_is_renewed_on_the_same_connection() {
    let mut bench = common::Bench::new();
    // Tokens of three seconds: the client takes them to last two minutes, the least it believes,
    // so the server ends each control call with TOKEN_EXPIRED before the client would renew it.
    let server = bench
        .server_with_token_lifetime(Duration::from_secs(3))
        .await;
    let (link, credentials) = link_with(&mut bench, &server, ClientOptions::default()).await;
    let statuses = record_status(&link);
    connected(&link, &statuses).await;

    tokio::time::sleep(Duration::from_secs(7)).await;

    assert_eq!(bench.open_sessions(&server, &credentials.client_id), 1);
    assert!(greet(&link).await.ends_with(": hi"));
    assert_eq!(
        states(&statuses),
        [LinkState::Connecting, LinkState::Connected],
        "renewed twice, and nobody heard of it"
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
async fn a_handover_is_learned_on_the_control_channel_saved_by_the_app_and_acknowledged() {
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
    // Time for an acknowledgement to arrive, had one been sent.
    tokio::time::sleep(Duration::from_millis(500)).await;

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

#[tokio::test]
async fn a_handover_the_app_could_not_save_is_offered_to_it_again_on_the_next_connection() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, credentials) = link_with(&mut bench, &server, ClientOptions::default()).await;
    let tried: Recorder<usize> = Recorder::new();
    let to = tried.clone();
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    link.on_pins_changed(move |_| {
        let to = to.clone();
        let calls = calls.clone();
        async move {
            let call = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            to.record(call);
            if call == 1 {
                Err(std::io::Error::other("disk full"))
            } else {
                Ok(())
            }
        }
    });
    let statuses = record_status(&link);
    connected(&link, &statuses).await;
    bench.prepare(&server).await;
    tried.wait(|n| *n == 1).await;
    assert!(
        !bench
            .clients(&server)
            .await
            .iter()
            .any(|c| c.0 == credentials.client_id && c.2),
        "not acknowledged while unsaved"
    );

    // The server says it again on a new connection, and this time the app can save it.
    bench.end_all(&server).await;

    tried.wait(|n| *n == 2).await;
    acknowledged(&mut bench, &server, &credentials.client_id).await;
    link.stop().await;
}
