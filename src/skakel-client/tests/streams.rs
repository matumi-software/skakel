//! Streams against a real server: opening, each on a connection of its own, refusals with their
//! reason and words, how they end, and the serial type.

mod common;

use std::time::{Duration, Instant};

use common::within;
use tonic::Code;
use skakel_client::{
    Bytes, ClientOptions, Credentials, DataBits, ErrorCode, FailureKind, FlowControl, Frame,
    LineSettings, Link, OpenResult, Parity, Pins, SerialEvent, StopBits, StreamCloseReason,
    StreamRefusal, StreamRefusalReason,
};

fn data(bytes: &'static [u8]) -> Option<Frame> {
    Some(Frame::Data(Bytes::from_static(bytes)))
}

/// A link that is not started: streams and requests work without the control channel.
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

fn settings(baud: u32) -> LineSettings {
    LineSettings {
        baud,
        data_bits: DataBits::Eight,
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

    let opened = link.open_stream("echo", b"a b").await.unwrap();

    assert!(opened.is_open());
    let stream = opened.stream().unwrap();
    assert_eq!(stream.stream_type(), "echo");
    stream.send_data(&b"ping"[..]).await.unwrap();
    assert_eq!(stream.recv().await, data(b"ping"));
    assert_eq!(stream.close_info(), None);

    stream.close().await;

    let close = stream.close_info().unwrap();
    assert_eq!(close.reason, StreamCloseReason::Normal);
    assert_eq!(close.code, Code::Ok);
    assert_eq!(stream.recv().await, None);
}

#[tokio::test]
async fn a_stream_is_also_an_async_reader_and_writer_for_its_data() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;
    let stream = link
        .open_stream("echo", b"a b")
        .await
        .unwrap()
        .stream()
        .unwrap();
    let mut io = stream.into_io();

    io.write_all(b"ping pong").await.unwrap();
    let mut back = [0u8; 9];
    within(Duration::from_secs(20), io.read_exact(&mut back))
        .await
        .unwrap();
    assert_eq!(&back, b"ping pong");

    // A write of more than a frame goes out in parts and comes back whole.
    let big = vec![7u8; 200_000];
    io.write_all(&big).await.unwrap();
    let mut echoed = vec![0u8; big.len()];
    within(Duration::from_secs(20), io.read_exact(&mut echoed))
        .await
        .unwrap();
    assert_eq!(echoed, big);

    // Shutting down the writing side ends the call; reading then runs to the end.
    io.shutdown().await.unwrap();
    let mut rest = Vec::new();
    within(Duration::from_secs(20), io.read_to_end(&mut rest))
        .await
        .unwrap();
    assert!(rest.is_empty());
    assert_eq!(io.close_info().unwrap().reason, StreamCloseReason::Normal);
    assert!(io.write_all(b"late").await.is_err());
}

#[tokio::test]
async fn data_and_control_frames_keep_their_order() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;
    let stream = link
        .open_stream("echo", b"a")
        .await
        .unwrap()
        .stream()
        .unwrap();

    stream.send_data(&b"one"[..]).await.unwrap();
    stream.send_control(&b"\x08\x02"[..]).await.unwrap();
    stream.send_data(&b"three"[..]).await.unwrap();

    assert_eq!(stream.recv().await, data(b"one"));
    assert_eq!(
        stream.recv().await,
        Some(Frame::Control(Bytes::from_static(b"\x08\x02")))
    );
    assert_eq!(stream.recv().await, data(b"three"));
    stream.close().await;
}

#[tokio::test]
async fn a_stream_that_the_app_stopped_reading_loses_nothing() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;
    let stream = link
        .open_stream("echo", b"a")
        .await
        .unwrap()
        .stream()
        .unwrap();

    // Far more frames than wait in the buffer, sent before anything is read.
    for i in 0..200u32 {
        stream.send_data(i.to_be_bytes().to_vec()).await.unwrap();
    }

    for i in 0..200u32 {
        let frame = within(Duration::from_secs(20), stream.recv()).await;
        assert_eq!(frame, Some(Frame::Data(i.to_be_bytes().to_vec().into())));
    }
    stream.close().await;
}

#[tokio::test]
async fn open_stream_returns_a_refusal_with_its_reason_and_words() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;
    let cases: [(&str, &[u8], Code, StreamRefusalReason, &str); 4] = [
        (
            "echo",
            b"",
            Code::InvalidArgument,
            StreamRefusalReason::BadTarget,
            "Say which target.",
        ),
        (
            "echo",
            b"missing",
            Code::NotFound,
            StreamRefusalReason::NoSuchTarget,
            "There is no target called missing.",
        ),
        (
            "echo",
            b"busy",
            Code::FailedPrecondition,
            StreamRefusalReason::InUse,
            "bench-2 holds busy.",
        ),
        (
            "nope",
            b"a",
            Code::NotFound,
            StreamRefusalReason::NoSuchType,
            "This server has no stream type 'nope'.",
        ),
    ];

    for (stream_type, target, code, reason, words) in cases {
        let opened = link.open_stream(stream_type, target).await.unwrap();

        assert!(!opened.is_open());
        assert_eq!(
            opened.refusal(),
            Some(&StreamRefusal {
                code,
                reason,
                message: words.to_owned()
            })
        );
    }
}

#[tokio::test]
async fn each_stream_opens_a_connection_of_its_own_pinned_like_the_rest() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let credentials = bench.register(&server).await;
    let proxy = common::CountingProxy::start(server.port).await;
    let link = Link::new(
        &proxy.address(),
        server.pins(),
        credentials.clone(),
        ClientOptions::default(),
    )
    .unwrap();
    link.access_token().await.unwrap();

    let before = proxy.connections();
    let first = link
        .open_stream("echo", b"a")
        .await
        .unwrap()
        .stream()
        .unwrap();
    let after_first = proxy.connections();
    let second = link
        .open_stream("echo", b"b")
        .await
        .unwrap()
        .stream()
        .unwrap();
    let after_second = proxy.connections();
    first.send_data(&b"one"[..]).await.unwrap();
    second.send_data(&b"two"[..]).await.unwrap();

    assert_eq!((after_first - before, after_second - after_first), (1, 1));
    assert_eq!(first.recv().await, data(b"one"));
    assert_eq!(second.recv().await, data(b"two"));
    let wrong = Link::new(
        &server.address(),
        Pins::new(&vec!["0F"; 32].join(":")).unwrap(),
        credentials,
        ClientOptions::default(),
    )
    .unwrap();
    assert_eq!(
        wrong.open_stream("echo", b"a").await.unwrap_err().kind(),
        FailureKind::CertificateMismatch
    );
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

    let error = link.open_stream("stall", b"").await.unwrap_err();

    assert_eq!(error.kind(), FailureKind::Unreachable);
}

#[tokio::test]
async fn open_stream_refuses_a_type_that_is_not_one_and_open_serial_an_empty_port() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;

    assert_eq!(
        link.open_stream("Not A Type", b"")
            .await
            .unwrap_err()
            .kind(),
        FailureKind::InvalidRequest
    );
    assert_eq!(
        link.open_serial("").await.err().map(|e| e.kind()),
        Some(FailureKind::InvalidRequest)
    );
}

#[tokio::test]
async fn a_client_the_server_revoked_cannot_open_a_stream() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, credentials) = linked(&mut bench, &server).await;
    bench.revoke(&server, &credentials.client_id).await;

    let error = link.open_stream("echo", b"a").await.unwrap_err();

    assert_eq!(error.kind(), FailureKind::RejectedCredentials);
}

#[tokio::test]
async fn a_target_that_goes_away_ends_with_target_gone() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;

    let stream = link
        .open_stream("echo", b"vanish")
        .await
        .unwrap()
        .stream()
        .unwrap();

    let close = within(Duration::from_secs(20), stream.closed()).await;
    assert_eq!(close.reason, StreamCloseReason::TargetGone);
    assert_eq!(close.code, Code::NotFound);
    assert_eq!(close.description.as_deref(), Some("unplugged"));
    assert_eq!(
        close.message(),
        "What the stream was for went away on the server."
    );
    assert_eq!(stream.recv().await, None);
}

#[tokio::test]
async fn revoking_the_client_ends_its_streams_with_revoked() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, credentials) = linked(&mut bench, &server).await;
    let stream = link
        .open_stream("echo", b"a")
        .await
        .unwrap()
        .stream()
        .unwrap();

    bench.revoke(&server, &credentials.client_id).await;

    let close = within(Duration::from_secs(20), stream.closed()).await;
    assert_eq!(close.reason, StreamCloseReason::Revoked);
    assert_eq!(close.code, Code::Unauthenticated);
}

#[tokio::test]
async fn a_server_that_ends_every_stream_ends_them_with_stopping() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;
    let stream = link
        .open_stream("echo", b"a")
        .await
        .unwrap()
        .stream()
        .unwrap();
    // The server tracks a stream once it is running; a frame that came back has been through that.
    stream.send_data(&b"x"[..]).await.unwrap();
    stream.recv().await.unwrap();

    bench.end_all(&server).await;

    let close = within(Duration::from_secs(20), stream.closed()).await;
    assert_eq!(close.reason, StreamCloseReason::ServerStopping);
    assert_eq!(close.code, Code::Unavailable);
}

#[tokio::test]
async fn a_stream_stays_open_while_both_ends_ping_it() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;
    let stream = link
        .open_stream("echo", b"a")
        .await
        .unwrap()
        .stream()
        .unwrap();

    // Longer than one keep-alive interval, with nothing sent.
    tokio::time::sleep(Duration::from_secs(17)).await;

    assert_eq!(stream.close_info(), None);
    stream.send_data(&b"still here"[..]).await.unwrap();
    assert_eq!(stream.recv().await, data(b"still here"));
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
        Some(Bytes::from_static(b"AT\r\n"))
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
        data_bits: DataBits::Seven,
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
        Some(Bytes::from_static(b"x"))
    );
    assert_eq!(serial.stream().close_info(), None);
    serial.close().await;
}

#[tokio::test]
async fn a_port_that_reports_a_fault_ends_with_port_fault() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;

    let serial = open_serial(&link, "fault").await;

    let close = within(Duration::from_secs(20), serial.closed()).await;
    assert_eq!(close.reason, StreamCloseReason::TypeDefined);
    assert_eq!(close.code, Code::Aborted);
    assert_eq!(
        close.type_reason.as_deref(),
        Some(skakel_serial::PORT_FAULT)
    );
}

#[tokio::test]
async fn a_second_client_gets_in_use_and_an_unknown_port_no_such_target() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;

    let busy = link.open_serial("busy").await.unwrap();
    let missing = link.open_serial("COM9").await.unwrap();

    let OpenResult::Refused(busy) = busy else {
        panic!("refused");
    };
    assert_eq!(
        (busy.code, busy.reason),
        (Code::FailedPrecondition, StreamRefusalReason::InUse)
    );
    assert_eq!(busy.message, "bench-2 holds busy.");
    let OpenResult::Refused(missing) = missing else {
        panic!("refused");
    };
    assert_eq!(
        (missing.code, missing.reason),
        (Code::NotFound, StreamRefusalReason::NoSuchTarget)
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
        .send_control(skakel_serial::ClientMessage::LineSettings(settings(12_345)).encode())
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

/// Not a check: how fast one stream carries bulk bytes from the Rust client to the server over
/// loopback. Run with `cargo test --release -p skakel-client --test streams -- --ignored
/// --nocapture`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "a measurement, not a check"]
async fn throughput_of_one_stream_over_loopback() {
    let mut bench = common::Bench::new();
    let server = bench.server().await;
    let (link, _) = linked(&mut bench, &server).await;
    let stream = link
        .open_stream("echo", b"sink")
        .await
        .unwrap()
        .stream()
        .unwrap();
    let chunk = Bytes::from(vec![0x5Au8; 64 * 1024]);
    let total: u64 = 1024 * 1024 * 1024;

    let started = Instant::now();
    for _ in 0..total / chunk.len() as u64 {
        stream.send_data(chunk.clone()).await.unwrap();
    }
    stream.close().await;
    let counted = match stream.recv().await {
        Some(Frame::Control(bytes)) => u64::from_be_bytes(bytes[..8].try_into().unwrap()),
        other => panic!("no count: {other:?}"),
    };
    let seconds = started.elapsed().as_secs_f64();

    assert_eq!(counted, total);
    eprintln!(
        "one stream, {} MiB in 64 KiB frames: {:.2} s, {:.0} MiB/s",
        total >> 20,
        seconds,
        (total >> 20) as f64 / seconds
    );
}
