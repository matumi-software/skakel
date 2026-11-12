//! What the integration tests share: a server wired like an app (its own gRPC service, an `echo`
//! stream type and a pretend `serial` port), and small clients that speak HTTPS over HTTP/1.1 and
//! gRPC over HTTP/2 to it, over TLS with no certificate check, so the tests do not depend on the
//! Rust client.

#![allow(dead_code)]

pub mod greeter;

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use prost::Message as _;
use prost::bytes::Bytes;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use serde_json::Value;
use skakel_proto::v2::control_service_client::ControlServiceClient;
use skakel_proto::v2::stream_service_client::StreamServiceClient;
use skakel_proto::v2::{
    FlowControl, LineSettings, ModemStatus, OpenRequest, OpenResponse, Parity, SerialClientMessage,
    SerialError, SerialErrorCode, SerialOpened, SerialServerMessage, SerialTarget, StopBits,
    StreamOpen, open_request, open_response, serial_client_message, serial_server_message,
};
use skakel_server::{
    InMemoryStore, SkakelServer, SkakelServerBuilder, StreamEnd, StreamMessage,
    StreamOpen as Opening, StreamRequest, StreamSession, connection_builder,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_stream::wrappers::ReceiverStream;
use tonic::body::Body;
use tonic::codegen::http;
use tonic::{Status, Streaming};
use tonic_types::StatusExt;

pub const APP_ID: &str = "test-app";
pub const APP_VERSION: &str = "1.2.3";
pub const NAME: &str = "rust-bench";

/// The test stream type. The target is text: none is `BAD_TARGET`, `missing` `NO_SUCH_TARGET`,
/// `busy` `IN_USE`, `vanish` opens and ends at once with `TARGET_GONE`, `abort` opens and ends with
/// a reason of its own, `slow` opens and does not read for two seconds, `late` takes a second to
/// open, `sink` counts the data it gets and, once the client ends its side, sends the count as a
/// control frame (eight bytes, big-endian), `huge` opens and sends one data frame over the 16 MiB
/// limit, and anything else echoes what it receives.
pub fn echo_stream() -> impl skakel_server::StreamHandler {
    |request: StreamRequest| async move {
        match std::str::from_utf8(&request.target).unwrap_or("") {
            "" => Opening::BadTarget("Say which target.".into()),
            "missing" => Opening::NotFound("There is no target called missing.".into()),
            "busy" => Opening::InUse("bench-2 holds busy.".into()),
            "vanish" => Opening::accept(|session: StreamSession| async move {
                session.end(StreamEnd::target_gone("unplugged")).await;
            }),
            "abort" => Opening::accept(|session: StreamSession| async move {
                session
                    .end(StreamEnd::aborted("WORN_OUT", "The echo is worn out.").unwrap())
                    .await;
            }),
            "slow" => Opening::accept(|session: StreamSession| async move {
                tokio::time::sleep(Duration::from_secs(2)).await;
                echo(session).await;
            }),
            "late" => {
                tokio::time::sleep(Duration::from_secs(1)).await;
                Opening::accept(echo)
            }
            "sink" => Opening::accept(sink),
            "huge" => Opening::accept(|session: StreamSession| async move {
                let _ = session.send_data(vec![7u8; 16 * 1024 * 1024 + 1]).await;
                session.ended().await;
            }),
            _ => Opening::accept(echo),
        }
    }
}

async fn sink(mut session: StreamSession) {
    let mut total = 0u64;
    while let Some(message) = session.recv().await {
        if let StreamMessage::Data(data) = message {
            total += data.len() as u64;
        }
    }
    let _ = session.send_control(total.to_be_bytes().to_vec()).await;
}

async fn echo(mut session: StreamSession) {
    while let Some(message) = session.recv().await {
        if session.send(message).await.is_err() {
            return;
        }
    }
}

fn settings_9600() -> LineSettings {
    LineSettings {
        baud: 9600,
        data_bits: 8,
        parity: Parity::None as i32,
        stop_bits: StopBits::One as i32,
        flow_control: FlowControl::None as i32,
    }
}

fn server_message(message: serial_server_message::Message) -> Bytes {
    SerialServerMessage {
        message: Some(message),
    }
    .encode_to_vec()
    .into()
}

/// A serial port as an app would serve it, with the port played by a loopback: bytes sent come
/// back. `COM1` opens; `fault` opens and then reports a fault (`PORT_FAULT`); `busy` is `IN_USE`;
/// no port is `BAD_TARGET`; anything else `NO_SUCH_TARGET`. 12345 baud is a rate the port cannot
/// do. Setting DTR raises DSR and DCD.
pub fn serial_stream() -> impl skakel_server::StreamHandler {
    |request: StreamRequest| async move {
        let port = SerialTarget::decode(request.target.clone())
            .map(|t| t.port)
            .unwrap_or_default();
        match port.as_str() {
            "" => Opening::BadTarget("Say which port.".into()),
            "busy" => Opening::InUse("bench-2 holds busy.".into()),
            "COM1" | "fault" => Opening::accept(move |session| pretend_serial(session, port)),
            other => Opening::NotFound(format!("There is no port {other}.")),
        }
    }
}

async fn pretend_serial(mut session: StreamSession, port: String) {
    let mut settings = settings_9600();
    let opened = serial_server_message::Message::Opened(SerialOpened {
        line_settings: Some(settings),
        modem_status: Some(ModemStatus {
            cts: true,
            dsr: false,
            dcd: false,
            ri: false,
        }),
    });
    if session.send_control(server_message(opened)).await.is_err() {
        return;
    }
    if port == "fault" {
        session
            .end(StreamEnd::aborted("PORT_FAULT", "The port reported a fault.").unwrap())
            .await;
        return;
    }
    while let Some(message) = session.recv().await {
        let reply = match message {
            StreamMessage::Data(data) => {
                if session.send_data(data).await.is_err() {
                    return;
                }
                continue;
            }
            StreamMessage::Control(control) => {
                match SerialClientMessage::decode(control)
                    .ok()
                    .and_then(|m| m.message)
                {
                    Some(serial_client_message::Message::LineSettings(change))
                        if change.baud == 12345 =>
                    {
                        serial_server_message::Message::Error(SerialError {
                            code: SerialErrorCode::Unsupported as i32,
                            detail: "This port cannot run at 12345 baud.".into(),
                        })
                    }
                    Some(serial_client_message::Message::LineSettings(change)) => {
                        settings = change;
                        serial_server_message::Message::LineSettings(settings)
                    }
                    Some(serial_client_message::Message::ModemLines(lines))
                        if lines.dtr.is_some() =>
                    {
                        let dtr = lines.dtr == Some(true);
                        serial_server_message::Message::ModemStatus(ModemStatus {
                            cts: true,
                            dsr: dtr,
                            dcd: dtr,
                            ri: false,
                        })
                    }
                    _ => continue,
                }
            }
        };
        if session.send_control(server_message(reply)).await.is_err() {
            return;
        }
    }
}

/// A builder for the bench server on loopback, with a free TCP port and discovery on a free UDP
/// port, before it starts.
pub fn bench_builder() -> SkakelServerBuilder {
    bench_builder_with(Arc::new(InMemoryStore::new()))
}

pub fn bench_builder_with(store: Arc<InMemoryStore>) -> SkakelServerBuilder {
    SkakelServerBuilder::new(APP_ID, APP_VERSION, store)
        .name(NAME)
        .listen("127.0.0.1:0".parse().unwrap())
        .discovery_bind("127.0.0.1".parse().unwrap())
        .discovery_port(0)
        .grpc_service(greeter::Greeter)
        .stream("echo", echo_stream())
        .stream("serial", serial_stream())
}

pub async fn start() -> SkakelServer {
    bench_builder().start().await.expect("the server starts")
}

// ---- an app that serves Skakel on a listener of its own ----

/// The page the app serves beside Skakel.
pub const APP_PAGE: &str = "/app/page";

/// Starts `builder` without a listener, mounted on an app's own server on loopback, the way the
/// crate docs show: an axum router with a page of the app's own and Skakel's service as its
/// fallback, a TLS acceptor from the server's settings, the caller's address put on every request,
/// and Skakel's connection settings. The server's `local_addr` is the app's port, so the helpers
/// below reach Skakel through the app.
pub async fn start_mounted_with(builder: SkakelServerBuilder) -> SkakelServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = builder
        .start_mounted(listener.local_addr().unwrap())
        .await
        .expect("the server starts");
    let app = axum::Router::new()
        .route(
            APP_PAGE,
            axum::routing::get(|| async { "the app's own page" }),
        )
        .fallback_service(server.service());
    let acceptor = TlsAcceptor::from(server.tls_config());
    tokio::spawn(async move {
        loop {
            let Ok((tcp, remote)) = listener.accept().await else {
                continue;
            };
            let (acceptor, app) = (acceptor.clone(), app.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let service = hyper::service::service_fn(
                    move |mut request: hyper::Request<hyper::body::Incoming>| {
                        request
                            .extensions_mut()
                            .insert(axum::extract::ConnectInfo(remote));
                        let mut app = app.clone();
                        async move { tower_service::Service::call(&mut app, request).await }
                    },
                );
                let _ = connection_builder()
                    .serve_connection_with_upgrades(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    server
}

/// The bench server mounted on an app's own server.
pub async fn start_mounted() -> SkakelServer {
    start_mounted_with(bench_builder()).await
}

// ---- TLS that trusts anything, and records what the server presented ----

#[derive(Debug)]
pub struct AcceptAnything {
    pub presented: Mutex<Option<Vec<u8>>>,
}

impl ServerCertVerifier for AcceptAnything {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.presented.lock().unwrap() = Some(end_entity.as_ref().to_vec());
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A TLS client config that trusts anything, offering `alpn`, and its verifier.
pub fn tls_config(alpn: &[&[u8]]) -> (Arc<ClientConfig>, Arc<AcceptAnything>) {
    let verifier = Arc::new(AcceptAnything {
        presented: Mutex::new(None),
    });
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    (Arc::new(config), verifier)
}

pub type Tls = tokio_rustls::client::TlsStream<TcpStream>;

/// A TLS connection to `address` with `config`.
pub async fn tls_with(address: SocketAddr, config: Arc<ClientConfig>) -> Tls {
    let tcp = TcpStream::connect(address).await.unwrap();
    tls_over(tcp, config).await
}

/// A TLS connection to `address` from the local address `from`, such as 127.0.0.2, offering
/// HTTP/1.1 only or HTTP/2 too.
pub async fn tls_from(address: SocketAddr, from: IpAddr, http1_only: bool) -> Tls {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind(SocketAddr::new(from, 0)).unwrap();
    let tcp = socket.connect(address).await.unwrap();
    let alpn: &[&[u8]] = if http1_only {
        &[b"http/1.1"]
    } else {
        &[b"h2", b"http/1.1"]
    };
    tls_over(tcp, tls_config(alpn).0).await
}

async fn tls_over(tcp: TcpStream, config: Arc<ClientConfig>) -> Tls {
    tcp.set_nodelay(true).unwrap();
    TlsConnector::from(config)
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .expect("the TLS handshake")
}

/// A TLS connection to `address`, offering HTTP/1.1 only or HTTP/2 too, and the certificate the
/// server presented.
pub async fn tls(address: SocketAddr, http1_only: bool) -> (Tls, Vec<u8>) {
    let alpn: &[&[u8]] = if http1_only {
        &[b"http/1.1"]
    } else {
        &[b"h2", b"http/1.1"]
    };
    let (config, verifier) = tls_config(alpn);
    let stream = tls_with(address, config).await;
    let presented = verifier
        .presented
        .lock()
        .unwrap()
        .clone()
        .expect("a certificate was presented");
    (stream, presented)
}

/// The fingerprint of the certificate the server presents now.
pub async fn presented_fingerprint(address: SocketAddr) -> String {
    let (_, der) = tls(address, true).await;
    skakel_wire::fingerprints::of_der(&der)
}

// ---- HTTPS over HTTP/1.1 ----

#[derive(Debug)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|_| panic!("not JSON: {}", self.text()))
    }

    /// The problem's `detail`.
    pub fn detail(&self) -> String {
        self.json()["detail"].as_str().unwrap_or("").to_owned()
    }
}

fn parse_reply(raw: &[u8]) -> Reply {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("no header end in {:?}", String::from_utf8_lossy(raw)));
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = head.lines();
    let status: u16 = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect();
    let body = raw[split + 4..].to_vec();
    let chunked = headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.eq_ignore_ascii_case("chunked")
    });
    Reply {
        status,
        headers,
        body: if chunked { dechunk(&body) } else { body },
    }
}

fn dechunk(mut body: &[u8]) -> Vec<u8> {
    let mut out = vec![];
    while let Some(line_end) = body.windows(2).position(|w| w == b"\r\n") {
        let size =
            usize::from_str_radix(std::str::from_utf8(&body[..line_end]).unwrap().trim(), 16)
                .unwrap_or(0);
        if size == 0 {
            break;
        }
        out.extend_from_slice(&body[line_end + 2..line_end + 2 + size]);
        body = &body[line_end + 2 + size + 2..];
    }
    out
}

async fn exchange<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    mut stream: S,
    request: Vec<u8>,
) -> Reply {
    stream.write_all(&request).await.unwrap();
    let mut raw = vec![];
    // The server may close without a clean TLS shutdown; what arrived is what counts.
    let _ = stream.read_to_end(&mut raw).await;
    parse_reply(&raw)
}

pub struct Request<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub headers: Vec<(&'a str, String)>,
    pub body: Vec<u8>,
    /// Send the body with this declared length instead of its own.
    pub declared_length: Option<usize>,
}

impl<'a> Request<'a> {
    pub fn new(method: &'a str, path: &'a str) -> Self {
        Self {
            method,
            path,
            headers: vec![],
            body: vec![],
            declared_length: None,
        }
    }

    pub fn get(path: &'a str) -> Self {
        Self::new("GET", path)
    }

    pub fn header(mut self, name: &'a str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }

    pub fn bearer(self, token: &str) -> Self {
        self.header("Authorization", format!("Bearer {token}"))
    }

    pub fn json(mut self, body: &Value) -> Self {
        self.headers
            .push(("Content-Type", "application/json".into()));
        self.body = body.to_string().into_bytes();
        self
    }

    pub fn form(mut self, body: &str) -> Self {
        self.headers
            .push(("Content-Type", "application/x-www-form-urlencoded".into()));
        self.body = body.as_bytes().to_vec();
        self
    }

    pub fn bytes(&self) -> Vec<u8> {
        let mut head = format!(
            "{} {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n",
            self.method, self.path
        );
        for (name, value) in &self.headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        if !self.body.is_empty() || self.method == "POST" {
            head.push_str(&format!(
                "Content-Length: {}\r\n",
                self.declared_length.unwrap_or(self.body.len())
            ));
        }
        head.push_str("\r\n");
        let mut bytes = head.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }

    /// Sends it over TLS to the server.
    pub async fn send(self, server: &SkakelServer) -> Reply {
        self.send_to(server.local_addr()).await
    }

    /// Sends it over TLS to `address`.
    pub async fn send_to(self, address: SocketAddr) -> Reply {
        let (stream, _) = tls(address, true).await;
        exchange(stream, self.bytes()).await
    }

    /// Sends it over TLS to the server from the local address `from`.
    pub async fn send_from(self, server: &SkakelServer, from: &str) -> Reply {
        let stream = tls_from(server.local_addr(), from.parse().unwrap(), true).await;
        exchange(stream, self.bytes()).await
    }

    /// Sends it over a plain TCP connection to the TLS port.
    pub async fn send_plain(self, server: &SkakelServer) -> Reply {
        let stream = TcpStream::connect(server.local_addr()).await.unwrap();
        exchange(stream, self.bytes()).await
    }
}

/// Registers a client without pairing and gets a token for it.
pub async fn client_with_token(
    server: &SkakelServer,
    name: &str,
) -> (skakel_server::NewClient, String) {
    let client = server.clients().register(name).await.unwrap();
    let token = token_for(server, &client.client_id, &client.client_secret).await;
    (client, token)
}

pub async fn token_for(server: &SkakelServer, id: &str, secret: &str) -> String {
    let reply = token_request(server, id, secret).await;
    assert_eq!(reply.status, 200, "{}", reply.text());
    reply.json()["access_token"].as_str().unwrap().to_owned()
}

pub async fn token_request(server: &SkakelServer, id: &str, secret: &str) -> Reply {
    Request::new("POST", "/skakel/v2/token")
        .form(&format!(
            "grant_type=client_credentials&client_id={id}&client_secret={secret}"
        ))
        .send(server)
        .await
}

// ---- gRPC over HTTP/2 ----

/// One HTTP/2 connection to the server, for the generated gRPC clients. Each call goes out on it
/// with the scheme and authority filled in.
#[derive(Clone)]
pub struct Grpc {
    send: SendRequest<Body>,
    authority: String,
    /// The protocol ALPN chose.
    pub alpn: Option<Vec<u8>>,
}

impl tower_service::Service<http::Request<Body>> for Grpc {
    type Response = http::Response<hyper::body::Incoming>;
    type Error = hyper::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.send.poll_ready(cx)
    }

    fn call(&mut self, mut request: http::Request<Body>) -> Self::Future {
        let path = request
            .uri()
            .path_and_query()
            .map_or("/", |p| p.as_str())
            .to_owned();
        *request.uri_mut() = format!("https://{}{path}", self.authority).parse().unwrap();
        Box::pin(self.send.send_request(request))
    }
}

/// An HTTP/2 connection over `stream`, already through TLS.
pub async fn grpc_over<S>(stream: S, authority: String, alpn: Option<Vec<u8>>) -> Grpc
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (send, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .timer(TokioTimer::new())
        .adaptive_window(true)
        .handshake(TokioIo::new(stream))
        .await
        .expect("the HTTP/2 handshake");
    tokio::spawn(connection);
    Grpc {
        send,
        authority,
        alpn,
    }
}

/// A new HTTP/2 connection to the server.
pub async fn grpc(server: &SkakelServer) -> Grpc {
    grpc_to(server.local_addr()).await
}

/// A new HTTP/2 connection to `address`.
pub async fn grpc_to(address: SocketAddr) -> Grpc {
    let (stream, _) = tls(address, false).await;
    let alpn = stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    grpc_over(stream, format!("localhost:{}", address.port()), alpn).await
}

pub fn control(connection: &Grpc) -> ControlServiceClient<Grpc> {
    ControlServiceClient::new(connection.clone())
}

pub fn streams(connection: &Grpc) -> StreamServiceClient<Grpc> {
    StreamServiceClient::new(connection.clone())
        .max_decoding_message_size(64 << 20)
        .max_encoding_message_size(64 << 20)
}

/// A request that carries `token` as its bearer token.
pub fn with_token<T>(message: T, token: &str) -> tonic::Request<T> {
    let mut request = tonic::Request::new(message);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
}

/// The domain and reason of a status's `ErrorInfo`.
pub fn reason_of(status: &Status) -> Option<(String, String)> {
    status
        .get_details_error_info()
        .map(|info| (info.domain, info.reason))
}

/// The status's code and its Skakel reason, for a short assertion.
pub fn refused(status: &Status) -> (tonic::Code, String) {
    let reason = match reason_of(status) {
        Some((domain, reason)) if domain == "skakel" => reason,
        Some((domain, reason)) => format!("{domain}/{reason}"),
        None => String::new(),
    };
    (status.code(), reason)
}

/// A control call's requests, and its answers.
pub struct ControlCall {
    pub requests: mpsc::Sender<skakel_proto::v2::ConnectRequest>,
    pub answers: Streaming<skakel_proto::v2::ConnectResponse>,
}

impl ControlCall {
    /// The next answer, within ten seconds: `Ok(None)` when the call ended with `OK`.
    pub async fn next(
        &mut self,
    ) -> Result<Option<skakel_proto::v2::connect_response::Message>, Status> {
        let answer = tokio::time::timeout(Duration::from_secs(10), self.answers.message())
            .await
            .expect("an answer within ten seconds")?;
        Ok(answer.map(|a| a.message.expect("a message of a known kind")))
    }
}

/// Opens `ControlService.Connect` with `token` on `connection`.
pub async fn connect(connection: &Grpc, token: &str) -> Result<ControlCall, Status> {
    let (requests, rx) = mpsc::channel(8);
    let answers = control(connection)
        .connect(with_token(ReceiverStream::new(rx), token))
        .await?
        .into_inner();
    Ok(ControlCall { requests, answers })
}

/// An open stream: what goes out, and what comes back.
pub struct TestStream {
    pub frames: mpsc::Sender<OpenRequest>,
    pub answers: Streaming<OpenResponse>,
}

impl TestStream {
    pub async fn send_data(&self, data: impl Into<Bytes>) {
        self.frames
            .send(OpenRequest {
                frame: Some(open_request::Frame::Data(data.into())),
            })
            .await
            .expect("the stream takes frames");
    }

    pub async fn send_control(&self, control: impl Into<Bytes>) {
        self.frames
            .send(OpenRequest {
                frame: Some(open_request::Frame::Control(control.into())),
            })
            .await
            .expect("the stream takes frames");
    }

    /// The next frame within ten seconds: `Ok(None)` when the stream ended with `OK`.
    pub async fn next(&mut self) -> Result<Option<open_response::Frame>, Status> {
        self.next_within(Duration::from_secs(10)).await
    }

    pub async fn next_within(
        &mut self,
        limit: Duration,
    ) -> Result<Option<open_response::Frame>, Status> {
        let answer = tokio::time::timeout(limit, self.answers.message())
            .await
            .expect("a frame within the limit")?;
        Ok(answer.map(|a| a.frame.expect("a frame of a known kind")))
    }
}

/// Opens a stream of `stream_type` for `target` with `token` on `connection`, and waits for
/// `opened`.
pub async fn open_stream_on(
    connection: &Grpc,
    token: &str,
    stream_type: &str,
    target: &[u8],
) -> Result<TestStream, Status> {
    let (frames, rx) = mpsc::channel(16);
    frames
        .send(OpenRequest {
            frame: Some(open_request::Frame::Open(StreamOpen {
                stream_type: stream_type.into(),
                target: Bytes::copy_from_slice(target),
            })),
        })
        .await
        .unwrap();
    let answers = streams(connection)
        .open(with_token(ReceiverStream::new(rx), token))
        .await?
        .into_inner();
    let mut stream = TestStream { frames, answers };
    match stream.next().await? {
        Some(open_response::Frame::Opened(_)) => Ok(stream),
        other => panic!("the first frame is not opened: {other:?}"),
    }
}

/// Opens a stream on a connection of its own.
pub async fn open_stream(
    server: &SkakelServer,
    token: &str,
    stream_type: &str,
    target: &[u8],
) -> Result<TestStream, Status> {
    let connection = grpc(server).await;
    open_stream_on(&connection, token, stream_type, target).await
}

/// The encoded target of a `serial` stream.
pub fn serial_target(port: &str) -> Vec<u8> {
    SerialTarget { port: port.into() }.encode_to_vec()
}

/// Waits until `check` holds, for up to five seconds.
pub async fn eventually(what: &str, check: impl Fn() -> bool) {
    for _ in 0..250 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("{what} never happened");
}
