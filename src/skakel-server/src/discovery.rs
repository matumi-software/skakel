//! Answers discovery probes on a UDP socket.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use skakel_wire::discovery::net::should_answer;
use skakel_wire::discovery::{DiscoveryAnswer, create_answer};
use skakel_wire::{SkakelApp, VERSIONS};
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
///
/// It answers on an IPv4 socket and, when the server's HTTPS also serves IPv6 (or the bind address
/// is an IPv6 one), on an IPv6 socket of its own on the same port, so a client that probes over
/// IPv6 is answered at an address it can use.
pub(crate) struct Discovery {
    state: Arc<ServerState>,
    announcement: Announcement,
    bind: IpAddr,
    /// Whether HTTPS is served over IPv6 too, so an IPv6 answer leads somewhere.
    serves_ipv6: bool,
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
    tasks: Vec<JoinHandle<()>>,
}

impl Discovery {
    pub(crate) fn new(
        state: Arc<ServerState>,
        announcement: Announcement,
        bind: IpAddr,
        serves_ipv6: bool,
        port: u16,
        server_stopped: watch::Receiver<bool>,
    ) -> Self {
        Self {
            state,
            announcement,
            bind,
            serves_ipv6,
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
        let sockets = bind_sockets(self.bind, self.serves_ipv6, port).await?;
        let address = sockets[0].local_addr()?;
        let (stop, stopped) = watch::channel(false);
        let tasks = sockets
            .into_iter()
            .map(|socket| {
                tokio::spawn(answer(
                    socket,
                    self.state.clone(),
                    Announcement {
                        name: self.announcement.name.clone(),
                        port: self.announcement.port,
                        app: self.announcement.app.clone(),
                    },
                    stopped.clone(),
                    self.server_stopped.clone(),
                ))
            })
            .collect();
        *running = Some(Running { stop, tasks });
        *self.address.lock().unwrap() = Some(address);
        *self.last_port.lock().unwrap() = Some(address.port());
        Ok(address)
    }

    /// Stops answering and releases the UDP port before it returns. Does nothing when it is not
    /// answering.
    pub(crate) async fn stop(&self) {
        let mut running = self.running.lock().await;
        if let Some(Running { stop, tasks }) = running.take() {
            stop.send_replace(true);
            for task in tasks {
                let _ = task.await;
            }
        }
        self.address.lock().unwrap().take();
    }

    /// The address answering, when it is.
    pub(crate) fn address(&self) -> Option<SocketAddr> {
        *self.address.lock().unwrap()
    }
}

/// The sockets discovery answers on, the first one the one whose address is reported. An IPv4
/// bind address gets an IPv4 socket, and the unspecified one (the default) also an IPv6 one when
/// HTTPS is served over IPv6; an IPv6 bind address gets an IPv6 socket, and the unspecified one
/// also an IPv4 socket. The second socket is best effort: a host without IPv6, or a port that is
/// taken on the other family, costs that family only, and is logged.
async fn bind_sockets(bind: IpAddr, serves_ipv6: bool, port: u16) -> io::Result<Vec<UdpSocket>> {
    match bind {
        IpAddr::V4(address) => {
            let first = UdpSocket::bind(SocketAddr::new(IpAddr::V4(address), port)).await?;
            let mut sockets = vec![first];
            if address.is_unspecified() && serves_ipv6 {
                let port = sockets[0].local_addr()?.port();
                push_best_effort(&mut sockets, bind_ipv6(Ipv6Addr::UNSPECIFIED, port));
            }
            Ok(sockets)
        }
        IpAddr::V6(address) => {
            let first = bind_ipv6(address, port)?;
            let mut sockets = vec![first];
            if address.is_unspecified() {
                let port = sockets[0].local_addr()?.port();
                push_best_effort(&mut sockets, bind_ipv4(Ipv4Addr::UNSPECIFIED, port).await);
            }
            Ok(sockets)
        }
    }
}

async fn bind_ipv4(address: Ipv4Addr, port: u16) -> io::Result<UdpSocket> {
    UdpSocket::bind(SocketAddr::new(IpAddr::V4(address), port)).await
}

/// An IPv6-only UDP socket. IPv6 only, so it never takes the IPv4 packets of the same port on a
/// system where a wildcard IPv6 socket would (Linux by default); the IPv4 socket answers those.
fn bind_ipv6(address: Ipv6Addr, port: u16) -> io::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_only_v6(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddr::new(IpAddr::V6(address), port).into())?;
    UdpSocket::from_std(socket.into())
}

fn push_best_effort(sockets: &mut Vec<UdpSocket>, bound: io::Result<UdpSocket>) {
    match bound {
        Ok(socket) => sockets.push(socket),
        Err(error) => log::warn!("Discovery will not answer on the other address family: {error}"),
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
