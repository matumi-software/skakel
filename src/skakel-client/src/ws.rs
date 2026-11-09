//! Opens a WebSocket with the upgrade written out by hand, over a pinned HTTP client, as reqwest
//! does inside for any request. Done here so a refusal keeps its body: the server checks everything
//! before the upgrade, and its problem `detail` is what a person reads. A WebSocket library's own
//! handshake would drop it.

use std::time::Duration;

use reqwest::{StatusCode, Url, Version};
use skakel_protocol::SkakelProblem;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::handshake::client::generate_key;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};

use crate::failure::{Error, bad_answer};

/// The most of a refusal's body that is read.
const MAX_PROBLEM_BYTES: usize = 16 * 1024;

/// A WebSocket over an upgraded HTTP connection.
pub(crate) type Socket = WebSocketStream<reqwest::Upgraded>;

/// What asking for the upgrade gave.
#[expect(
    clippy::large_enum_variant,
    reason = "one of these is made per connection, and the socket is the point"
)]
pub(crate) enum Opened {
    /// The server switched protocols.
    Open(Socket),
    /// The server refused before the upgrade, with its status and the problem's `detail`.
    Refused { status: u16, detail: Option<String> },
}

/// Asks for the upgrade with a bearer token. The upgrade and the reading of a refusal together take
/// at most `timeout`; an open socket has no time limit of its own.
pub(crate) async fn open(
    client: &reqwest::Client,
    url: Url,
    token: &str,
    timeout: Duration,
    max_message_size: usize,
) -> Result<Opened, Error> {
    let key = generate_key();
    let request = client
        .get(url)
        .version(Version::HTTP_11)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", &key)
        .bearer_auth(token);
    tokio::time::timeout(timeout, async {
        let response = request.send().await.map_err(Error::from_cause)?;
        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            let status = response.status().as_u16();
            return Ok(Opened::Refused {
                status,
                detail: read_detail(response).await,
            });
        }
        let accepts: Vec<_> = response
            .headers()
            .get_all("Sec-WebSocket-Accept")
            .iter()
            .collect();
        let expected = derive_accept_key(key.as_bytes());
        if accepts.len() != 1 || accepts[0].to_str().ok() != Some(expected.as_str()) {
            return Err(bad_answer(
                "The server switched protocols without a single WebSocket accept for this key.",
            ));
        }
        let upgraded = response.upgrade().await.map_err(Error::from_cause)?;
        let config = WebSocketConfig::default()
            .max_message_size(Some(max_message_size))
            .max_frame_size(Some(max_message_size));
        Ok(Opened::Open(
            WebSocketStream::from_raw_socket(upgraded, Role::Client, Some(config)).await,
        ))
    })
    .await
    .map_err(Error::from_cause)?
}

/// The problem's `detail`, or `None` when the body is not a problem.
async fn read_detail(mut response: reqwest::Response) -> Option<String> {
    let mut body = Vec::new();
    while body.len() < MAX_PROBLEM_BYTES {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                body.extend_from_slice(&chunk[..chunk.len().min(MAX_PROBLEM_BYTES - body.len())])
            }
            Ok(None) => break,
            // A body that took too long or broke off: the status alone still says why.
            Err(_) => return None,
        }
    }
    serde_json::from_slice::<SkakelProblem>(&body).ok()?.detail
}
