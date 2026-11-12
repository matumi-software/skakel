//! Answers discovery probes on a UDP socket.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use skakel_discovery::net::should_answer;
use skakel_discovery::{DiscoveryAnswer, create_answer};
use skakel_protocol::{SkakelApp, VERSIONS};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;

use crate::state::ServerState;

/// What the answerer announces.
pub(crate) struct Announcement {
    pub name: String,
    pub port: u16,
    pub app: SkakelApp,
}

/// The discovery answerer of a server, which can be started and stopped while the server runs.
pub(crate) struct Discovery {
    state: Arc<ServerState>,
    announcement: Announcement,
    bind: IpAddr,
    port: u16,
    server_stopped: watch::Receiver<bool>,
    running: Mutex<Option<Running>>,
    /// The address answered on, readable without waiting for a start or stop in progress.
    address: StdMutex<Option<SocketAddr>>,
    /// The port of the last bind, so a restart on a configured port of 0 takes the same one.
    last_port: StdMutex<Option<u16>>,
}

struct Running {
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl Discovery {
    pub(crate) fn new(
        state: Arc<ServerState>,
        announcement: Announcement,
        bind: IpAddr,
        port: u16,
        server_stopped: watch::Receiver<bool>,
    ) -> Self {
        Self {
            state,
            announcement,
            bind,
            port,
            server_stopped,
            running: Mutex::new(None),
            address: StdMutex::new(None),
            last_port: StdMutex::new(None),
        }
    }

    /// Binds the UDP port and starts answering. Does nothing but give the address when it is
    /// already answering.
    pub(crate) async fn start(&self) -> io::Result<SocketAddr> {
        let mut running = self.running.lock().await;
        if running.is_some()
            && let Some(address) = self.address()
        {
            return Ok(address);
        }
        // A port of 0 takes a free one the first time. After that the same port is asked for
        // again, so what the server announces to the network does not change.
        if *self.server_stopped.borrow() {
            return Err(io::Error::other("the server has stopped"));
        }
        let port = match (self.port, *self.last_port.lock().unwrap()) {
            (0, Some(last)) => last,
            (port, _) => port,
        };
        let socket = UdpSocket::bind(SocketAddr::new(self.bind, port)).await?;
        let address = socket.local_addr()?;
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(answer(
            socket,
            self.state.clone(),
            Announcement {
                name: self.announcement.name.clone(),
                port: self.announcement.port,
                app: self.announcement.app.clone(),
            },
            stopped,
            self.server_stopped.clone(),
        ));
        *running = Some(Running { stop, task });
        *self.address.lock().unwrap() = Some(address);
        *self.last_port.lock().unwrap() = Some(address.port());
        Ok(address)
    }

    /// Stops answering and releases the UDP port before it returns. Does nothing when it is not
    /// answering.
    pub(crate) async fn stop(&self) {
        let mut running = self.running.lock().await;
        if let Some(Running { stop, task }) = running.take() {
            stop.send_replace(true);
            let _ = task.await;
        }
        self.address.lock().unwrap().take();
    }

    /// The address answering, when it is.
    pub(crate) fn address(&self) -> Option<SocketAddr> {
        *self.address.lock().unwrap()
    }
}

/// Answers probes until `stopped` or `server_stopped` says stop. The answer is made again
/// whenever the certificate (and so the fingerprint) changes.
async fn answer(
    socket: UdpSocket,
    state: Arc<ServerState>,
    announcement: Announcement,
    mut stopped: watch::Receiver<bool>,
    mut server_stopped: watch::Receiver<bool>,
) {
    let mut cached: Option<(String, Vec<u8>)> = None;
    let mut buffer = [0u8; 2048];
    loop {
        let received = tokio::select! {
            _ = stopped.changed() => return,
            _ = server_stopped.changed() => return,
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
                versions: VERSIONS.to_vec(),
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
