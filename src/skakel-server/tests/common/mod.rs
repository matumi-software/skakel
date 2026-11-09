//! What the integration tests share: a server wired like an app (a hub with `Greet`,
//! `Echo` and `Connection`, an `echo` stream type and a pretend `serial` port), and a small client
//! that speaks HTTP, WebSocket and the SignalR hub protocol over TLS to it with no certificate
//! check, so the tests do not depend on the Rust client.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use serde_json::{Value, json};
use skakel_serial::{
    ClientMessage, ErrorCode, FlowControl, LineSettings, ModemStatus, Parity, ServerMessage,
    StopBits,
};
use skakel_server::{
    BoxFuture, HubCall, HubError, HubHandler, InMemoryStore, SkakelServer, SkakelServerBuilder,
    StreamHandler, StreamMessage, StreamOpen, StreamRequest, StreamSession,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;

pub const APP_ID: &str = "test-app";
pub const APP_VERSION: &str = "1.2.3";
pub const NAME: &str = "rust-bench";

/// The app's hub: `Greet` answers with a `Greeted` message, `Echo` returns its argument and
/// `Connection` the connection's id. Anything else is an error.
pub struct TestHub;

impl HubHandler for TestHub {
    fn invoke(&self, call: HubCall) -> BoxFuture<'_, Result<Option<Value>, HubError>> {
        Box::pin(async move {
            let text = call.arguments.first().and_then(Value::as_str).unwrap_or("");
            match call.target.as_str() {
                "Greet" => {
                    call.connection.send(
                        "Greeted",
                        vec![json!(format!("{}: {}", call.connection.client_id, text))],
                    )?;
                    Ok(None)
                }
                "Echo" => Ok(Some(json!(text))),
                "Connection" => Ok(Some(json!(call.connection.connection_id))),
                _ => Err(HubError::new("Method does not exist.")),
            }
        })
    }
}

/// The test stream type. The query names a target: none is 422, `missing` 404, `busy` 409,
/// `vanish` opens and closes at once with 4004, anything else echoes what it receives.
pub fn echo_stream() -> StreamHandler {
    Arc::new(|request: StreamRequest| -> BoxFuture<'static, StreamOpen> {
        Box::pin(async move {
            match request.query_value("target").unwrap_or("") {
                "" => StreamOpen::Invalid("Say which target, as ?target=<name>.".into()),
                "missing" => StreamOpen::NotFound("There is no target called missing.".into()),
                "busy" => StreamOpen::InUse("bench-2 holds busy.".into()),
                "vanish" => StreamOpen::accept(|session: StreamSession| async move {
                    session.close(4004, "unplugged").await;
                }),
                _ => StreamOpen::accept(|mut session: StreamSession| async move {
                    while let Some(message) = session.recv().await {
                        if session.send(message).await.is_err() {
                            return;
                        }
                    }
                }),
            }
        })
    })
}

/// A serial port as an app would serve it, with the port played by a loopback: bytes sent come
/// back. `COM1` opens; `fault` opens and then reports a fault (4100); `busy` is 409; no port is
/// 422; anything else 404. 12345 baud is a rate the port cannot do. Setting DTR raises DSR and DCD.
pub fn serial_stream() -> StreamHandler {
    Arc::new(|request: StreamRequest| -> BoxFuture<'static, StreamOpen> {
        Box::pin(async move {
            let port = request.query_value("port").unwrap_or("").to_owned();
            match port.as_str() {
                "" => StreamOpen::Invalid("Say which port, as ?port=<id>.".into()),
                "busy" => StreamOpen::InUse("bench-2 holds busy.".into()),
                "COM1" | "fault" => {
                    StreamOpen::accept(move |session| pretend_serial(session, port))
                }
                other => StreamOpen::NotFound(format!("There is no port {other}.")),
            }
        })
    })
}

async fn pretend_serial(mut session: StreamSession, port: String) {
    let mut settings = LineSettings {
        baud: 9600,
        data_bits: 8,
        parity: Parity::None,
        stop_bits: StopBits::One,
        flow_control: FlowControl::None,
    };
    let opened = ServerMessage::Opened {
        line_settings: settings,
        modem_status: ModemStatus {
            cts: true,
            dsr: false,
            dcd: false,
            ri: false,
        },
    };
    if session.send_text(opened.to_json()).await.is_err() {
        return;
    }
    if port == "fault" {
        session
            .close(
                skakel_serial::CLOSE_PORT_FAULT,
                "The port reported a fault.",
            )
            .await;
        return;
    }
    while let Some(message) = session.recv().await {
        let reply = match message {
            StreamMessage::Binary(data) => {
                if session.send_binary(data).await.is_err() {
                    return;
                }
                continue;
            }
            StreamMessage::Text(text) => match ClientMessage::parse(&text) {
                Some(ClientMessage::LineSettings(change)) if change.baud == 12345 => {
                    ServerMessage::Error {
                        code: ErrorCode::Unsupported,
                        detail: Some("This port cannot run at 12345 baud.".into()),
                    }
                }
                Some(ClientMessage::LineSettings(change)) => {
                    settings = change;
                    ServerMessage::LineSettings(settings)
                }
                Some(ClientMessage::ModemLines { dtr: Some(dtr), .. }) => {
                    ServerMessage::ModemStatus(ModemStatus {
                        cts: true,
                        dsr: dtr,
                        dcd: dtr,
                        ri: false,
                    })
                }
                _ => continue,
            },
        };
        if session.send_text(reply.to_json()).await.is_err() {
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
        .hub("hub", TestHub)
        .stream("echo", echo_stream())
        .stream("serial", serial_stream())
}

pub async fn start() -> SkakelServer {
    bench_builder().start().await.expect("the server starts")
}

// ---- TLS that trusts anything, and records what the server presented ----

#[derive(Debug)]
struct AcceptAnything {
    presented: Mutex<Option<Vec<u8>>>,
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

/// A TLS connection to `address` and the certificate the server presented.
pub async fn tls(
    address: SocketAddr,
    http1_only: bool,
) -> (tokio_rustls::client::TlsStream<TcpStream>, Vec<u8>) {
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
    if http1_only {
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
    }
    let tcp = TcpStream::connect(address).await.unwrap();
    let stream = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .expect("the TLS handshake");
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
    skakel_protocol::fingerprints::of_der(&der)
}

// ---- HTTP ----

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
        let (stream, _) = tls(server.local_addr(), true).await;
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
    Request::new("POST", "/skakel/v1/token")
        .form(&format!(
            "grant_type=client_credentials&client_id={id}&client_secret={secret}"
        ))
        .send(server)
        .await
}

// ---- WebSocket ----

pub type Socket = tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>;

/// Opens a WebSocket at `path_and_query` with `token`, or returns the HTTP answer that refused it.
pub async fn open_socket(
    server: &SkakelServer,
    path_and_query: &str,
    token: Option<&str>,
) -> Result<Socket, Reply> {
    let (stream, _) = tls(server.local_addr(), true).await;
    let mut request = format!(
        "wss://localhost:{}{path_and_query}",
        server.local_addr().port()
    )
    .into_client_request()
    .unwrap();
    if let Some(token) = token {
        request.headers_mut().insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
    }
    match tokio_tungstenite::client_async(request, stream).await {
        Ok((socket, _)) => Ok(socket),
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => Err(Reply {
            status: response.status().as_u16(),
            headers: response
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_owned()))
                .collect(),
            body: response.body().clone().unwrap_or_default(),
        }),
        Err(other) => panic!("the WebSocket did not open: {other}"),
    }
}

/// The next frame, with a limit.
pub async fn next_frame(socket: &mut Socket) -> Option<Message> {
    next_frame_for(socket, std::time::Duration::from_secs(10)).await
}

/// The next frame, with a limit of your own.
pub async fn next_frame_for(socket: &mut Socket, limit: std::time::Duration) -> Option<Message> {
    tokio::time::timeout(limit, socket.next())
        .await
        .expect("a frame within the limit")
        .map(|m| m.expect("a readable frame"))
}

// ---- The SignalR hub, as a client ----

pub struct HubClient {
    pub socket: Socket,
    buffer: Vec<u8>,
    /// How long to wait for the next message.
    pub limit: std::time::Duration,
}

const RS: u8 = 0x1E;

/// Negotiates and connects the hub at `/skakel/v1/hub`, and does the handshake.
pub async fn hub_connect(server: &SkakelServer, token: &str) -> HubClient {
    let negotiated = Request::new("POST", "/skakel/v1/hub/negotiate?negotiateVersion=1")
        .bearer(token)
        .send(server)
        .await;
    assert_eq!(negotiated.status, 200, "{}", negotiated.text());
    let body = negotiated.json();
    let id = body["connectionToken"].as_str().unwrap();
    let mut socket = open_socket(server, &format!("/skakel/v1/hub?id={id}"), Some(token))
        .await
        .map_err(|r| format!("{}: {}", r.status, r.text()))
        .expect("the hub connects");
    socket
        .send(Message::text(format!(
            "{{\"protocol\":\"json\",\"version\":1}}{}",
            char::from(RS)
        )))
        .await
        .unwrap();
    let mut client = HubClient {
        socket,
        buffer: vec![],
        limit: std::time::Duration::from_secs(10),
    };
    assert_eq!(client.next_message().await.unwrap(), json!({}));
    client
}

impl HubClient {
    /// The next hub message, or `None` when the connection ended.
    pub async fn next_message(&mut self) -> Option<Value> {
        loop {
            if let Some(end) = self.buffer.iter().position(|b| *b == RS) {
                let record: Vec<u8> = self.buffer.drain(..=end).collect();
                return Some(serde_json::from_slice(&record[..record.len() - 1]).unwrap());
            }
            match next_frame_for(&mut self.socket, self.limit).await? {
                Message::Text(text) => self.buffer.extend_from_slice(text.as_bytes()),
                Message::Binary(data) => self.buffer.extend_from_slice(&data),
                Message::Close(_) => return None,
                _ => {}
            }
        }
    }

    /// The next message that is not a ping.
    pub async fn next_non_ping(&mut self) -> Option<Value> {
        loop {
            let message = self.next_message().await?;
            if message["type"] != 6 {
                return Some(message);
            }
        }
    }

    pub async fn send(&mut self, message: Value) {
        self.socket
            .send(Message::text(format!("{message}{}", char::from(RS))))
            .await
            .unwrap();
    }

    /// Invokes a method and returns its completion.
    pub async fn invoke(&mut self, id: &str, target: &str, arguments: Value) -> Value {
        self.send(
            json!({ "type": 1, "invocationId": id, "target": target, "arguments": arguments }),
        )
        .await;
        loop {
            let message = self.next_non_ping().await.expect("a completion");
            if message["type"] == 3 && message["invocationId"] == id {
                return message;
            }
        }
    }
}
