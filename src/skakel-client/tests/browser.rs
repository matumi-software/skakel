//! Discovery against a real server: the browser probes a loopback address and the server
//! answers as it does on a network.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::{free_udp, within};
use skakel_client::{Browser, BrowserOptions};

fn options(udp: u16, app_ids: Option<Vec<String>>) -> BrowserOptions {
    let options = BrowserOptions::new(5240)
        .probe_targets(vec![SocketAddr::from(([127, 0, 0, 1], udp))])
        .probe_interval(Duration::from_millis(300));
    match app_ids {
        Some(ids) => options.app_ids(ids),
        None => options,
    }
}

#[tokio::test]
async fn the_browser_lists_a_server_by_what_it_answers() {
    let mut bench = common::Bench::new();
    let udp = free_udp();
    let server = bench.server_with_discovery(udp).await;
    let browser = Browser::new(options(udp, Some(vec!["test-app".into()])));
    let mut changes = browser.watch();

    browser.start().await.unwrap();

    let list = within(
        Duration::from_secs(20),
        changes.wait_for(|list| !list.is_empty()),
    )
    .await
    .unwrap()
    .clone();
    assert_eq!(list.len(), 1);
    let found = &list[0];
    assert_eq!(found.name, "bench");
    assert_eq!(found.port, server.port);
    assert_eq!(found.address.to_string(), "127.0.0.1");
    assert_eq!(found.fingerprint, server.fingerprint);
    assert_eq!(found.app.id, "test-app");
    assert_eq!(found.app.version, "1.2.3");
    assert_eq!(found.versions, [2]);
    assert_eq!(found.version(), Some(2));
    assert_eq!(found.url(), server.address());
    assert!(found.other_endpoints.is_empty());
    assert!(browser.is_browsing());
    browser.stop();
}

#[tokio::test]
async fn the_browser_leaves_out_the_servers_of_other_apps() {
    let mut bench = common::Bench::new();
    let udp = free_udp();
    bench.server_with_discovery(udp).await;
    let browser = Browser::new(options(udp, Some(vec!["another-app".into()])));
    browser.start().await.unwrap();

    // Several probes go by: the server answers them all, and none is kept.
    tokio::time::sleep(Duration::from_secs(1)).await;

    assert!(browser.servers().is_empty());
    assert!(browser.entries().is_empty());
    browser.stop();
}

#[tokio::test]
async fn a_server_that_stops_answering_leaves_the_list() {
    let mut bench = common::Bench::new();
    let udp = free_udp();
    let server = bench.server_with_discovery(udp).await;
    let browser = Browser::new(options(udp, None));
    let mut changes = browser.watch();
    browser.start().await.unwrap();
    within(
        Duration::from_secs(20),
        changes.wait_for(|list| !list.is_empty()),
    )
    .await
    .unwrap();

    bench.stop(&server).await;

    within(
        Duration::from_secs(20),
        changes.wait_for(|list| list.is_empty()),
    )
    .await
    .unwrap();
    browser.stop();
}

#[tokio::test]
async fn stopping_empties_the_list_and_ends_the_probes() {
    let mut bench = common::Bench::new();
    let udp = free_udp();
    bench.server_with_discovery(udp).await;
    let browser = Browser::new(options(udp, None));
    let mut changes = browser.watch();
    browser.start().await.unwrap();
    within(
        Duration::from_secs(20),
        changes.wait_for(|list| !list.is_empty()),
    )
    .await
    .unwrap();

    browser.stop();

    assert!(!browser.is_browsing());
    assert!(browser.servers().is_empty());
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(
        browser.servers().is_empty(),
        "no probe goes out once it stopped"
    );
}
