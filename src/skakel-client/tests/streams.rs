//! Streams against a real server: opening, refusals with their detail, close codes, and the
//! serial type.

mod common;

use std::time::Duration;

use common::within;
use skakel_client::{
    ClientOptions, Credentials, ErrorCode, FailureKind, FlowControl, Frame, LineSettings, Link,
    OpenResult, Parity, SerialEvent, StopBits, StreamCloseReason, StreamRefusal,
    StreamRefusalReason,
};

/// A link that is not started: streams and requests work without the hub.
async fn linked(bench: &mut common::Bench, server: &common::Server) -> (Link, Credentials) {
    linked_with(bench, server, ClientOptions::default()).await
}

async fn linked_with(
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

fn settings(baud: i32) -> LineSettings {
    LineSettings {
        baud,
        data_bits: 8,
        parity: Parity::None,
        stop_bits: StopBits::One,
        flow_control: FlowControl::None,
    }
}

#[tokio::test]
async fn open_stream_opens_a_stream_that_carries_data_and_closes_normally() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;

    let opened = link
        .open_stream("echo", &[("target", "a b")])
        .await
        .unwrap();

    assert!(opened.is_open());
    let stream = opened.stream().unwrap();
    assert_eq!(stream.stream_type(), "echo");
    stream.send_binary(b"ping".to_vec()).await.unwrap();
    assert_eq!(stream.recv().await, Some(Frame::Binary(b"ping".to_vec())));
    assert_eq!(stream.close_info(), None);

    stream.close().await;

    let close = stream.close_info().unwrap();
    assert_eq!(close.reason, StreamCloseReason::Normal);
    assert_eq!(close.code, Some(1000));
    assert_eq!(stream.recv().await, None);
}

#[tokio::test]
async fn binary_and_text_frames_keep_their_order() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;
    let stream = link
        .open_stream("echo", &[("target", "a")])
        .await
        .unwrap()
        .stream()
        .unwrap();

    stream.send_binary(b"one".to_vec()).await.unwrap();
    stream.send_text(r#"{"op":"two"}"#).await.unwrap();
    stream.send_binary(b"three".to_vec()).await.unwrap();

    assert_eq!(stream.recv().await, Some(Frame::Binary(b"one".to_vec())));
    assert_eq!(
        stream.recv().await,
        Some(Frame::Text(r#"{"op":"two"}"#.into()))
    );
    assert_eq!(stream.recv().await, Some(Frame::Binary(b"three".to_vec())));
    stream.close().await;
}

#[tokio::test]
async fn a_stream_that_the_app_stopped_reading_loses_nothing() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;
    let stream = link
        .open_stream("echo", &[("target", "a")])
        .await
        .unwrap()
        .stream()
        .unwrap();

    // Far more frames than wait in the buffer, sent before anything is read.
    for i in 0..200u32 {
        stream.send_binary(i.to_be_bytes().to_vec()).await.unwrap();
    }

    for i in 0..200u32 {
        let frame = within(Duration::from_secs(20), stream.recv()).await;
        assert_eq!(frame, Some(Frame::Binary(i.to_be_bytes().to_vec())));
    }
    stream.close().await;
}

#[tokio::test]
async fn open_stream_returns_a_refusal_with_its_status_and_detail() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;
    let cases: [(&str, Option<&str>, u16, StreamRefusalReason, &str); 4] = [
        (
            "echo",
            None,
            422,
            StreamRefusalReason::InvalidQuery,
            "Say which target, as ?target=<name>.",
        ),
        (
            "echo",
            Some("missing"),
            404,
            StreamRefusalReason::NotFound,
            "There is no target called missing.",
        ),
        (
            "echo",
            Some("busy"),
            409,
            StreamRefusalReason::InUse,
            "bench-2 holds busy.",
        ),
        (
            "nope",
            Some("a"),
            404,
            StreamRefusalReason::NotFound,
            "This server has no stream type 'nope'.",
        ),
    ];

    for (stream_type, target, status, reason, detail) in cases {
        let query: Vec<(&str, &str)> = target.map(|t| ("target", t)).into_iter().collect();

        let opened = link.open_stream(stream_type, &query).await.unwrap();

        assert!(!opened.is_open());
        assert_eq!(
            opened.refusal(),
            Some(&StreamRefusal {
                status,
                reason,
                message: detail.to_owned()
            })
        );
    }
}

#[tokio::test]
async fn open_stream_gives_up_when_the_server_does_not_answer_within_the_request_timeout() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked_with(
        &mut bench,
        &server,
        ClientOptions {
            request_timeout: Duration::from_secs(1),
            ..ClientOptions::default()
        },
    )
    .await;

    let error = link.open_stream("stall", &[]).await.unwrap_err();

    assert_eq!(error.kind(), FailureKind::Unreachable);
}

#[tokio::test]
#[should_panic(expected = "A stream type is one or more of")]
async fn open_stream_refuses_a_type_that_is_not_one() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;

    let _ = link.open_stream("Not A Type", &[]).await;
}

#[tokio::test]
async fn a_client_the_server_revoked_cannot_open_a_stream() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, credentials) = linked(&mut bench, &server).await;
    bench.revoke(&server, &credentials.client_id).await;

    let error = link
        .open_stream("echo", &[("target", "a")])
        .await
        .unwrap_err();

    assert_eq!(error.kind(), FailureKind::RejectedCredentials);
}

#[tokio::test]
async fn a_target_that_goes_away_closes_with_4004() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;

    let stream = link
        .open_stream("echo", &[("target", "vanish")])
        .await
        .unwrap()
        .stream()
        .unwrap();

    let close = within(Duration::from_secs(20), stream.closed()).await;
    assert_eq!(close.reason, StreamCloseReason::TargetGone);
    assert_eq!(close.code, Some(4004));
    assert_eq!(close.description.as_deref(), Some("unplugged"));
    assert_eq!(
        close.message(),
        "What the stream was for went away on the server."
    );
    assert_eq!(stream.recv().await, None);
}

#[tokio::test]
async fn revoking_the_client_closes_its_streams_with_4001() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, credentials) = linked(&mut bench, &server).await;
    let stream = link
        .open_stream("echo", &[("target", "a")])
        .await
        .unwrap()
        .stream()
        .unwrap();

    bench.revoke(&server, &credentials.client_id).await;

    let close = within(Duration::from_secs(20), stream.closed()).await;
    assert_eq!(close.reason, StreamCloseReason::Revoked);
    assert_eq!(close.code, Some(4001));
}

#[tokio::test]
async fn a_server_that_ends_every_stream_closes_them_with_4003() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;
    let stream = link
        .open_stream("echo", &[("target", "a")])
        .await
        .unwrap()
        .stream()
        .unwrap();
    // The server tracks a stream once it is running; a frame that came back has been through that.
    stream.send_binary(b"x".to_vec()).await.unwrap();
    stream.recv().await.unwrap();

    bench.end_all(&server).await;

    let close = within(Duration::from_secs(20), stream.closed()).await;
    assert_eq!(close.reason, StreamCloseReason::ServerStopping);
    assert_eq!(close.code, Some(4003));
}

#[tokio::test]
async fn a_stream_stays_open_while_both_ends_ping_it() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;
    let stream = link
        .open_stream("echo", &[("target", "a")])
        .await
        .unwrap()
        .stream()
        .unwrap();

    // Longer than one keep-alive interval, with nothing sent.
    tokio::time::sleep(Duration::from_secs(17)).await;

    assert_eq!(stream.close_info(), None);
    stream.send_binary(b"still here".to_vec()).await.unwrap();
    assert_eq!(
        stream.recv().await,
        Some(Frame::Binary(b"still here".to_vec()))
    );
    stream.close().await;
}

async fn open_serial(link: &Link, port: &str) -> skakel_client::SerialConnection {
    link.open_serial(port).await.unwrap().stream().unwrap()
}

#[tokio::test]
async fn open_serial_gives_the_port_as_the_server_says_it_is() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;

    let serial = open_serial(&link, "COM1").await;

    assert_eq!(serial.line_settings(), settings(9600));
    let modem = serial.modem_status();
    assert!(modem.cts && !modem.dsr && !modem.dcd && !modem.ri);
    serial.close().await;
}

#[tokio::test]
async fn serial_bytes_go_both_ways() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;
    let serial = open_serial(&link, "COM1").await;

    serial.send(b"AT\r\n".to_vec()).await.unwrap();

    assert_eq!(
        within(Duration::from_secs(20), serial.recv()).await,
        Some(b"AT\r\n".to_vec())
    );
    serial.close().await;
    assert_eq!(serial.recv().await, None);
}

#[tokio::test]
async fn set_line_settings_waits_for_the_server_to_echo_them() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;
    let serial = open_serial(&link, "COM1").await;
    let wanted = LineSettings {
        baud: 115_200,
        data_bits: 7,
        parity: Parity::Even,
        stop_bits: StopBits::Two,
        flow_control: FlowControl::RtsCts,
    };

    let change = serial.set_line_settings(wanted).await.unwrap();

    assert!(change.applied);
    assert_eq!(change.line_settings, wanted);
    assert_eq!(change.detail, None);
    assert_eq!(serial.line_settings(), wanted);
    serial.close().await;
}

#[tokio::test]
async fn a_change_the_port_refuses_leaves_the_settings_as_they_were() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;
    let serial = open_serial(&link, "COM1").await;

    let change = serial.set_line_settings(settings(12_345)).await.unwrap();

    assert!(!change.applied);
    assert_eq!(change.line_settings, settings(9600));
    assert_eq!(
        change.detail.as_deref(),
        Some("This port cannot run at 12345 baud.")
    );
    assert_eq!(serial.line_settings(), settings(9600));
    serial.close().await;
}

#[tokio::test]
async fn a_change_the_server_never_answers_gives_up_and_lets_the_next_one_through() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;
    let serial = open_serial(&link, "COM1").await;
    serial.set_change_timeout(Duration::from_millis(500));

    let error = serial
        .set_line_settings(settings(54_321))
        .await
        .unwrap_err();

    assert_eq!(error.kind(), FailureKind::UnexpectedAnswer);
    let wanted = settings(115_200);
    let change = serial.set_line_settings(wanted).await.unwrap();
    assert!(change.applied);
    assert_eq!(change.line_settings, wanted);
    serial.close().await;
}

#[tokio::test]
async fn a_late_answer_is_not_taken_for_the_next_change() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;
    let serial = open_serial(&link, "COM1").await;
    serial.set_change_timeout(Duration::from_millis(200));
    let slow = serial.set_line_settings(settings(4800)).await;
    assert!(slow.is_err());
    serial.set_change_timeout(Duration::from_secs(10));

    // The slow change's echo comes first, then this one's refusal.
    let refused = serial.set_line_settings(settings(12_345)).await.unwrap();

    assert!(!refused.applied);
    assert_eq!(
        refused.detail.as_deref(),
        Some("This port cannot run at 12345 baud.")
    );
    assert_eq!(
        serial.line_settings().baud,
        4800,
        "the slow change was applied in the end"
    );
    serial.close().await;
}

#[tokio::test]
async fn setting_dtr_raises_the_input_lines_the_port_reports() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;
    let serial = open_serial(&link, "COM1").await;
    let mut events = serial.events();

    serial.set_modem_lines(Some(true), None).await.unwrap();

    let event = within(Duration::from_secs(20), events.recv())
        .await
        .unwrap();
    let SerialEvent::ModemStatus(status) = event else {
        panic!("a modem status: {event:?}");
    };
    assert!(status.dsr && status.dcd);
    assert_eq!(serial.modem_status(), status);
    serial.close().await;
}

#[tokio::test]
async fn break_and_purge_reach_the_server_without_ending_the_stream() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;
    let serial = open_serial(&link, "COM1").await;

    serial.set_break(true).await.unwrap();
    serial.set_break(false).await.unwrap();
    serial.purge(true, true).await.unwrap();

    // The port still works: the control messages were taken in order before this byte.
    serial.send(b"x".to_vec()).await.unwrap();
    assert_eq!(
        within(Duration::from_secs(20), serial.recv()).await,
        Some(b"x".to_vec())
    );
    assert_eq!(serial.stream().close_info(), None);
    serial.close().await;
}

#[tokio::test]
async fn a_port_that_reports_a_fault_closes_with_4100() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;

    let serial = open_serial(&link, "fault").await;

    let close = within(Duration::from_secs(20), serial.closed()).await;
    assert_eq!(close.reason, StreamCloseReason::TypeDefined);
    assert_eq!(close.code, Some(skakel_serial::CLOSE_PORT_FAULT));
}

#[tokio::test]
async fn a_second_client_gets_409_and_an_unknown_port_404() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;

    let busy = link.open_serial("busy").await.unwrap();
    let missing = link.open_serial("COM9").await.unwrap();

    let OpenResult::Refused(busy) = busy else {
        panic!("refused");
    };
    assert_eq!(
        (busy.status, busy.reason),
        (409, StreamRefusalReason::InUse)
    );
    assert_eq!(busy.message, "bench-2 holds busy.");
    let OpenResult::Refused(missing) = missing else {
        panic!("refused");
    };
    assert_eq!(
        (missing.status, missing.reason),
        (404, StreamRefusalReason::NotFound)
    );
    assert_eq!(missing.message, "There is no port COM9.");
}

#[tokio::test]
async fn an_unsupported_error_that_no_change_waits_for_is_an_event() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;
    let serial = open_serial(&link, "COM1").await;
    let mut events = serial.events();

    // Sent past the connection's own change handling, so nobody waits for the answer.
    serial
        .stream()
        .send_text(r#"{"op":"lineSettings","baud":12345,"dataBits":8,"parity":"none","stopBits":"1","flowControl":"none"}"#)
        .await
        .unwrap();

    let event = within(Duration::from_secs(20), events.recv())
        .await
        .unwrap();
    assert!(
        matches!(
            event,
            SerialEvent::Error {
                code: ErrorCode::Unsupported,
                ..
            }
        ),
        "{event:?}"
    );
    serial.close().await;
}
