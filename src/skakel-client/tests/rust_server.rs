//! The Rust client against the Rust server (`skakel-server`, in this process, on loopback): the
//! second criterion of issue #22, on protocol version 3. Discovery, info, pairing, the control
//! channel and the app's own gRPC service, streams, the serial stream, a revoke and a certificate
//! handover, with the server's own API standing in for the app.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::greeter::{self, GreetRequest};
use common::{Recorder, within};
use skakel_client::{
    Browser, BrowserOptions, Bytes, ClientOptions, FailureKind, Frame, GrpcCode, LineSettings,
    Link, LinkState, LinkStatus, OpenResult, PairingClient, Pins, StreamCloseReason, Url,
    read_info,
};
use skakel_server::{
    InMemoryStore, SkakelServer, SkakelServerBuilder, StreamMessage, StreamOpen, StreamRequest,
    StreamSession,
};
use tonic::Request;

fn echo() -> impl skakel_server::StreamHandler {
    |request: StreamRequest| async move {
        match &request.target[..] {
            b"" => StreamOpen::BadTarget("Say which target.".into()),
            b"busy" => StreamOpen::InUse("bench-2 holds busy.".into()),
            _ => StreamOpen::accept(|mut session: StreamSession| async move {
                while let Some(message) = session.recv().await {
                    if session.send(message).await.is_err() {
                        return;
                    }
                }
            }),
        }
    }
}

fn serial() -> impl skakel_server::StreamHandler {
    |request: StreamRequest| async move {
        if skakel_serial::port_of(&request.target).as_deref() != Some("COM1") {
            return StreamOpen::NotFound("There is no such port.".into());
        }
        StreamOpen::accept(|mut session: StreamSession| async move {
            let mut settings = LineSettings {
                baud: 9600,
                data_bits: skakel_client::DataBits::Eight,
                parity: skakel_client::Parity::None,
                stop_bits: skakel_client::StopBits::One,
                flow_control: skakel_client::FlowControl::None,
            };
            let opened = skakel_serial::ServerMessage::Opened {
                line_settings: settings,
                modem_status: skakel_client::ModemStatus {
                    cts: true,
                    dsr: false,
                    dcd: false,
                    ri: false,
                },
            };
            if session.send_control(opened.encode()).await.is_err() {
                return;
            }
            while let Some(message) = session.recv().await {
                match message {
                    StreamMessage::Data(data) => {
                        if session.send_data(data).await.is_err() {
                            return;
                        }
                    }
                    StreamMessage::Control(control) => {
                        if let Ok(skakel_serial::ClientMessage::LineSettings {
                            request_id,
                            settings: change,
                        }) = skakel_serial::ClientMessage::decode(&control)
                        {
                            settings = change;
                            let answer = skakel_serial::ServerMessage::LineSettings {
                                request_id,
                                settings,
                            };
                            if session.send_control(answer.encode()).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
        })
    }
}

async fn start() -> SkakelServer {
    SkakelServerBuilder::new("test-app", "1.2.3", Arc::new(InMemoryStore::new()))
        .name("rust-bench")
        .listen("127.0.0.1:0".parse().unwrap())
        .discovery_bind("127.0.0.1".parse().unwrap())
        .discovery_port(0)
        .grpc_service(greeter::Greeter)
        .stream("echo", echo())
        .stream("serial", serial())
        .start()
        .await
        .expect("the server starts")
}

fn address(server: &SkakelServer) -> Url {
    Url::parse(&format!(
        "https://127.0.0.1:{}/",
        server.local_addr().port()
    ))
    .unwrap()
}

fn pins(server: &SkakelServer) -> Pins {
    Pins::new(&server.fingerprint()).unwrap()
}

async fn linked(server: &SkakelServer) -> (Link, skakel_client::Credentials) {
    let client = server.clients().register("bench-1").await.unwrap();
    let credentials = skakel_client::Credentials::new(client.client_id, client.client_secret);
    let link = Link::new(
        &address(server),
        pins(server),
        credentials.clone(),
        ClientOptions::default(),
    )
    .unwrap();
    (link, credentials)
}

fn record_status(link: &Link) -> Recorder<LinkStatus> {
    common::record_status(link)
}

#[tokio::test]
async fn the_browser_finds_the_server_and_info_reads_what_it_says() {
    let server = start().await;
    let udp = server.discovery_addr().expect("discovery is on");
    let browser = Browser::new(
        BrowserOptions::new(5240)
            .app_ids(vec!["test-app".into()])
            .probe_targets(vec![SocketAddr::from(([127, 0, 0, 1], udp.port()))])
            .probe_interval(Duration::from_millis(300)),
    );
    let mut changes = browser.watch();
    browser.start().await.unwrap();

    let list = within(Duration::from_secs(20), changes.wait_for(|l| !l.is_empty()))
        .await
        .unwrap()
        .clone();

    assert_eq!(list[0].name, "rust-bench");
    assert_eq!(list[0].fingerprint, server.fingerprint());
    assert_eq!(list[0].port, server.local_addr().port());
    browser.stop();
    let info = read_info(&address(&server), &pins(&server), &ClientOptions::default())
        .await
        .unwrap();
    assert_eq!(
        (
            info.name.as_str(),
            info.app.id.as_str(),
            info.versions.as_slice()
        ),
        ("rust-bench", "test-app", [3].as_slice())
    );
}

#[tokio::test]
async fn pairing_hands_over_credentials_the_server_accepts() {
    let server = start().await;
    let mut pairing = PairingClient::open(
        &address(&server),
        &server.fingerprint(),
        "laptop",
        &ClientOptions::default(),
    )
    .await
    .unwrap();
    pairing.set_poll_interval(Duration::from_millis(100));
    let request = server.pairing().overview().await.requests.remove(0);
    assert_eq!(request.client_name, "laptop");

    server
        .pairing()
        .approve(&request.id, pairing.code())
        .await
        .unwrap();
    let credentials = pairing.wait().await.unwrap();

    assert_eq!(
        server.clients().name_of(&credentials.client_id).as_deref(),
        Some("laptop")
    );
    let link = Link::new(
        &address(&server),
        pairing.pins().clone(),
        credentials.clone(),
        ClientOptions::default(),
    )
    .unwrap();
    assert_eq!(link.hello().await.unwrap().client_id, credentials.client_id);
}

#[tokio::test]
async fn the_control_channel_carries_the_apps_calls_and_a_revoke_ends_the_link() {
    let server = start().await;
    let (link, credentials) = linked(&server).await;
    let statuses = record_status(&link);
    link.start();
    statuses.wait(|s| s.state == LinkState::Connected).await;

    let reply = greeter::greet(
        link.channel(),
        Request::new(GreetRequest {
            text: "hello".into(),
        }),
    )
    .await
    .unwrap();
    assert_eq!(reply.text, format!("{}: hello", credentials.client_id));

    server
        .clients()
        .revoke(&credentials.client_id)
        .await
        .unwrap();
    let closed = statuses.wait(|s| s.state == LinkState::Closed).await;
    assert_eq!(closed.failure.unwrap().kind(), FailureKind::Revoked);
    link.stop().await;
}

#[tokio::test]
async fn streams_and_the_serial_stream_work() {
    let server = start().await;
    let (link, _) = linked(&server).await;

    let stream = link
        .open_stream("echo", b"a")
        .await
        .unwrap()
        .stream()
        .unwrap();
    stream.send_data(&b"ping"[..]).await.unwrap();
    assert_eq!(
        stream.recv().await,
        Some(Frame::Data(Bytes::from_static(b"ping")))
    );
    stream.close().await;
    assert_eq!(
        stream.close_info().unwrap().reason,
        StreamCloseReason::Normal
    );

    let busy = link.open_stream("echo", b"busy").await.unwrap();
    assert_eq!(
        busy.refusal().map(|r| (r.code, r.message.as_str())),
        Some((GrpcCode::FailedPrecondition, "bench-2 holds busy."))
    );
    let refused = link.open_serial("COM9").await.unwrap();
    assert!(matches!(refused, OpenResult::Refused(r) if r.code == GrpcCode::NotFound));

    let port = link.open_serial("COM1").await.unwrap().stream().unwrap();
    assert_eq!(port.line_settings().baud, 9600);
    let wanted = LineSettings {
        baud: 115_200,
        ..port.line_settings()
    };
    assert!(port.set_line_settings(wanted).await.unwrap().applied);
    port.send(b"AT".to_vec()).await.unwrap();
    assert_eq!(
        within(Duration::from_secs(20), port.recv()).await,
        Some(Bytes::from_static(b"AT"))
    );
    port.close().await;
}

#[tokio::test]
async fn a_certificate_handover_is_learned_and_a_new_connection_shows_the_new_certificate() {
    let server = start().await;
    let (link, credentials) = linked(&server).await;
    let pins_seen: Recorder<Pins> = Recorder::new();
    let to = pins_seen.clone();
    link.set_pin_store(move |p| {
        let to = to.clone();
        async move {
            to.record(p);
            Ok::<(), std::convert::Infallible>(())
        }
    });
    let statuses = record_status(&link);
    link.start();
    statuses.wait(|s| s.state == LinkState::Connected).await;
    let current = server.fingerprint();

    let next = server
        .certificates()
        .prepare_next_certificate()
        .await
        .unwrap()
        .unwrap();
    pins_seen
        .wait(|p| {
            p.next_fingerprint()
                .is_some_and(|n| Pins::new(&next).unwrap().trusts(n))
        })
        .await;
    within(Duration::from_secs(15), async {
        while !server
            .clients()
            .all()
            .iter()
            .any(|c| c.has_next_certificate)
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    let switched = server
        .certificates()
        .switch_certificate()
        .await
        .unwrap()
        .unwrap();
    assert!(switched.not_received.is_empty());
    pins_seen
        .wait(|p| p.next_fingerprint().is_none() && p.trusts(&next))
        .await;

    let fresh = Link::new(
        &address(&server),
        link.pins(),
        credentials.clone(),
        ClientOptions::default(),
    )
    .unwrap();
    assert_eq!(
        fresh.hello().await.unwrap().client_id,
        credentials.client_id
    );
    let stale = Link::new(
        &address(&server),
        Pins::new(&current).unwrap(),
        credentials,
        ClientOptions::default(),
    )
    .unwrap();
    assert_eq!(
        stale.hello().await.unwrap_err().kind(),
        FailureKind::CertificateMismatch
    );
    link.stop().await;
}
