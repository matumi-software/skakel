//! The info call, version picking and pairing against a real server.

mod common;

use std::time::Duration;

use skakel_client::{
    ClientOptions, FailureKind, Link, PairingClient, PairingError, Pins, Url, read_info,
    require_version,
};

fn code_is_six_digits(code: &str) -> bool {
    code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit())
}

#[tokio::test]
async fn read_info_gives_the_servers_name_app_and_versions() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;

    let info = read_info(&server.address(), &server.pins(), &ClientOptions::default())
        .await
        .unwrap();

    assert_eq!(info.name, "bench");
    assert_eq!(info.app.id, "test-app");
    assert_eq!(info.app.version, "1.2.3");
    assert_eq!(info.versions, [2]);
    assert_eq!(require_version(&info.versions).unwrap(), 2);
}

#[tokio::test]
async fn read_info_refuses_a_server_with_another_certificate() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let other = Pins::new(&vec!["0F"; 32].join(":")).unwrap();

    let error = read_info(&server.address(), &other, &ClientOptions::default())
        .await
        .unwrap_err();

    assert_eq!(error.kind(), FailureKind::CertificateMismatch);
}

#[tokio::test]
async fn read_info_says_unreachable_for_a_port_nobody_listens_on() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let nobody = Url::parse(&format!("https://127.0.0.1:{}/", common::free_tcp())).unwrap();

    let error = read_info(&nobody, &server.pins(), &ClientOptions::default())
        .await
        .unwrap_err();

    assert_eq!(error.kind(), FailureKind::Unreachable);
    assert_eq!(
        error.to_string(),
        "Could not reach the server. Check the address and that the server is running."
    );
}

#[tokio::test]
async fn a_server_of_another_version_is_a_version_mismatch_with_both_sides_named() {
    let server = common::OtherVersion::start(&[1]).await;

    let info = read_info(&server.address(), &server.pins(), &ClientOptions::default())
        .await
        .unwrap();
    let error = require_version(&info.versions).unwrap_err();

    assert_eq!(info.versions, [1]);
    assert_eq!(error.kind(), FailureKind::VersionMismatch);
    assert_eq!(
        error.to_string(),
        "This server speaks Skakel 1 and this app speaks Skakel 2. Update the server."
    );
}

async fn open(server: &common::Server) -> PairingClient {
    PairingClient::open(
        &server.address(),
        &server.fingerprint,
        "laptop",
        &ClientOptions::default(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn wait_hands_over_credentials_once_the_code_is_typed_on_the_server() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let mut pairing = open(&server).await;
    pairing.set_poll_interval(Duration::from_millis(100));

    assert_eq!(pairing.server_name(), "bench");
    assert!(code_is_six_digits(pairing.code()), "{}", pairing.code());
    let requests = bench.requests(&server).await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].1, "laptop");
    assert_eq!(
        bench.approve(&server, &requests[0].0, pairing.code()).await,
        skakel_server::Approval::Approved,
        "both ends derived the same code"
    );

    let credentials = pairing.wait().await.unwrap();

    let clients = bench.clients(&server).await;
    assert_eq!(clients.len(), 1);
    assert_eq!(clients[0].0, credentials.client_id);
    assert_eq!(clients[0].1, "laptop");
    let link = Link::new(
        &server.address(),
        pairing.pins().clone(),
        credentials.clone(),
        ClientOptions::default(),
    )
    .unwrap();
    assert_eq!(link.hello().await.unwrap().client_id, credentials.client_id);
}

#[tokio::test]
async fn a_wrong_code_is_not_approved_and_the_request_waits() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let pairing = open(&server).await;
    let request = bench.requests(&server).await.remove(0).0;
    let wrong = if pairing.code() == "000000" {
        "000001"
    } else {
        "000000"
    };

    assert_eq!(
        bench.approve(&server, &request, wrong).await,
        skakel_server::Approval::WrongCode
    );

    assert_eq!(bench.requests(&server).await.len(), 1);
}

#[tokio::test]
async fn wait_reports_a_refusal() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let mut pairing = open(&server).await;
    pairing.set_poll_interval(Duration::from_millis(100));
    let request = bench.requests(&server).await.remove(0).0;
    assert!(bench.deny(&server, &request).await);

    let error = pairing.wait().await.unwrap_err();

    assert_eq!(error.kind(), FailureKind::PairingDenied);
    assert_eq!(error.to_string(), "The server refused the pairing request.");
}

#[tokio::test]
async fn withdraw_takes_a_waiting_request_off_the_server() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let pairing = open(&server).await;
    assert_eq!(bench.requests(&server).await.len(), 1);

    pairing.withdraw().await;

    assert!(bench.requests(&server).await.is_empty());
}

#[tokio::test]
async fn dropping_a_waiting_request_withdraws_it() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let pairing = open(&server).await;
    assert_eq!(bench.requests(&server).await.len(), 1);

    drop(pairing);

    for _ in 0..100 {
        if bench.requests(&server).await.is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the request was never withdrawn");
}

#[tokio::test]
async fn open_refuses_a_server_with_another_certificate_before_sending_anything() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let other = vec!["0F"; 32].join(":");

    let error = PairingClient::open(
        &server.address(),
        &other,
        "laptop",
        &ClientOptions::default(),
    )
    .await
    .unwrap_err();

    assert!(
        matches!(&error, PairingError::Failed(e) if e.kind() == FailureKind::CertificateMismatch),
        "{error:?}"
    );
    assert!(
        bench.requests(&server).await.is_empty(),
        "nothing was sent before the certificate was checked"
    );
}

#[tokio::test]
async fn open_refuses_a_name_that_is_empty_or_too_long() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;

    for name in ["", "   ", &"n".repeat(81)] {
        let error = PairingClient::open(
            &server.address(),
            &server.fingerprint,
            name,
            &ClientOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, PairingError::InvalidClientName), "{name:?}");
    }
    assert!(bench.requests(&server).await.is_empty());
}

#[tokio::test]
async fn open_refuses_a_server_that_speaks_no_common_version() {
    let server = common::OtherVersion::start(&[1]).await;

    let error = PairingClient::open(
        &server.address(),
        &server.fingerprint,
        "laptop",
        &ClientOptions::default(),
    )
    .await
    .unwrap_err();

    assert!(
        matches!(&error, PairingError::Failed(e) if e.kind() == FailureKind::VersionMismatch),
        "{error:?}"
    );
    assert_eq!(
        server.other_requests(),
        0,
        "nothing was asked past the info"
    );
}
