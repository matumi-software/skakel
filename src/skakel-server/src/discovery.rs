//! Answers discovery probes on a UDP socket.

use std::sync::Arc;
use std::time::Duration;

use skakel_discovery::net::should_answer;
use skakel_discovery::{DiscoveryAnswer, create_answer};
use skakel_protocol::{SkakelApp, VERSIONS};
use tokio::net::UdpSocket;
use tokio::sync::watch;

use crate::state::ServerState;

/// What the answerer announces.
pub(crate) struct Announcement {
    pub name: String,
    pub port: u16,
    pub app: SkakelApp,
}

/// Answers probes until `shutdown` says stop. The answer is made again whenever the certificate
/// (and so the fingerprint) changes.
pub(crate) async fn answer(
    socket: UdpSocket,
    state: Arc<ServerState>,
    announcement: Announcement,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut cached: Option<(String, Vec<u8>)> = None;
    let mut buffer = [0u8; 2048];
    loop {
        let received = tokio::select! {
            _ = shutdown.changed() => return,
            received = socket.recv_from(&mut buffer) => received,
        };
        let (length, from) = match received {
            Ok(received) => received,
            Err(_) => {
                // Windows reports an earlier answer that could not be delivered, or a datagram
                // larger than the buffer, on the next receive. Each is about one datagram, and
                // anyone on the network can send the second, so none may stop the answers.
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            }
        };
        let fingerprint = state.fingerprint();
        if cached
            .as_ref()
            .is_none_or(|(known, _)| *known != fingerprint)
        {
            let made = create_answer(&DiscoveryAnswer {
                name: announcement.name.clone(),
                port: announcement.port,
                fingerprint: fingerprint.clone(),
                app: announcement.app.clone(),
                versions: VERSIONS.iter().map(|v| *v as i32).collect(),
            });
            match made {
                Ok(bytes) => cached = Some((fingerprint, bytes)),
                Err(_) => continue,
            }
        }
        let Some((_, bytes)) = &cached else { continue };
        if should_answer(&buffer[..length], from, bytes) {
            // A failed send is about this one answer. The next probe still gets one.
            let _ = socket.send_to(bytes, from).await;
        }
    }
}
