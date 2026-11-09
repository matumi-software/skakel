//! The control channel, `skakel.v2.ControlService`: `Connect`, which tells a client the
//! certificates and why its calls end, and `Hello`.

use std::sync::Arc;
use std::time::Duration;

use skakel_proto::v2::control_service_server::ControlService;
use skakel_proto::v2::{
    Certificates, Closing, ClosingReason, ConnectRequest, ConnectResponse, HelloRequest,
    HelloResponse, connect_request, connect_response,
};
use skakel_protocol::Reason;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

use crate::crypto::Principal;
use crate::grpc::{ending, read_failed, token_refused};
use crate::http::ClientPrincipal;
use crate::server::Shared;
use crate::sessions::{ControlOut, SessionGuard, certificates_of};

/// How long the `closing` message gets to leave before the call ends.
const CLOSING_TIMEOUT: Duration = Duration::from_secs(2);

/// Messages waiting to go out on one control call.
const QUEUE: usize = 8;

/// The control service.
pub(crate) struct Control {
    pub shared: Arc<Shared>,
}

/// The principal the token check in front of every service put on the call.
pub(crate) fn principal_of<T>(request: &Request<T>) -> Result<Principal, Status> {
    request
        .extensions()
        .get::<ClientPrincipal>()
        .map(|principal| principal.0.clone())
        .ok_or_else(token_refused)
}

#[tonic::async_trait]
impl ControlService for Control {
    type ConnectStream = ReceiverStream<Result<ConnectResponse, Status>>;

    async fn connect(
        &self,
        request: Request<Streaming<ConnectRequest>>,
    ) -> Result<Response<Self::ConnectStream>, Status> {
        let principal = principal_of(&request)?;
        let inbound = request.into_inner();
        let (out, out_rx) = mpsc::channel(QUEUE);
        let (control_tx, control_rx) = mpsc::unbounded_channel();
        let guard = self.shared.sessions.add_control(
            &principal.client_id,
            principal.generation,
            control_tx,
        );
        tokio::spawn(run(
            self.shared.clone(),
            principal,
            inbound,
            out,
            control_rx,
            guard,
        ));
        Ok(Response::new(ReceiverStream::new(out_rx)))
    }

    async fn hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloResponse>, Status> {
        let principal = principal_of(&request)?;
        Ok(Response::new(HelloResponse {
            server: self.shared.name.clone(),
            client_id: principal.client_id,
        }))
    }
}

fn certificates(certificates: Certificates) -> ConnectResponse {
    ConnectResponse {
        message: Some(connect_response::Message::Certificates(certificates)),
    }
}

fn closing(reason: Reason) -> ConnectResponse {
    let reason = match reason {
        Reason::Revoked => ClosingReason::Revoked,
        Reason::Rotated => ClosingReason::Rotated,
        _ => ClosingReason::Stopping,
    };
    ConnectResponse {
        message: Some(connect_response::Message::Closing(Closing {
            reason: reason as i32,
        })),
    }
}

/// One `Connect` call, from the certificates it starts with to the status it ends with.
async fn run(
    shared: Arc<Shared>,
    principal: Principal,
    mut inbound: Streaming<ConnectRequest>,
    out: mpsc::Sender<Result<ConnectResponse, Status>>,
    mut control: mpsc::UnboundedReceiver<ControlOut>,
    _guard: SessionGuard,
) {
    if out
        .send(Ok(certificates(certificates_of(&shared.state))))
        .await
        .is_err()
    {
        return;
    }
    // The call is bound to its token's life; every other call is not.
    let until_expiry = (principal.expires_at - OffsetDateTime::now_utc())
        .try_into()
        .unwrap_or(Duration::ZERO);
    let expiry = tokio::time::sleep(until_expiry);
    tokio::pin!(expiry);
    let mut reading = true;
    loop {
        tokio::select! {
            biased;
            message = control.recv() => match message {
                Some(ControlOut::Certificates(now)) => {
                    if out.send(Ok(certificates(now))).await.is_err() {
                        return;
                    }
                }
                Some(ControlOut::Closing(reason)) => {
                    let _ = tokio::time::timeout(CLOSING_TIMEOUT, out.send(Ok(closing(reason)))).await;
                    let _ = tokio::time::timeout(CLOSING_TIMEOUT, out.send(Err(ending(reason)))).await;
                    return;
                }
                None => return,
            },
            () = &mut expiry => {
                let _ = out.send(Err(ending(Reason::TokenExpired))).await;
                return;
            }
            message = inbound.message(), if reading => match message {
                Ok(Some(ConnectRequest {
                    message: Some(connect_request::Message::NextCertificateReceived(received)),
                })) => {
                    let current = shared
                        .state
                        .loaded()
                        .is_current(&principal.client_id, principal.generation);
                    if current && !received.fingerprint.is_empty() {
                        let _ = shared
                            .state
                            .mark_next_certificate_received(&principal.client_id, &received.fingerprint)
                            .await;
                    }
                }
                // A kind this server does not know.
                Ok(Some(_)) => {}
                // The client has nothing more to say, but still wants the server's state.
                Ok(None) => reading = false,
                // A message over the limit, which ends the call as gRPC does, or a client that is
                // gone, which hears nothing more anyway.
                Err(status) => {
                    let _ = out.send(Err(read_failed(status))).await;
                    return;
                }
            },
            () = out.closed() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closing_carries_the_reason_as_the_proto_numbers_it() {
        let reason = |r| match closing(r).message {
            Some(connect_response::Message::Closing(c)) => c.reason,
            _ => panic!("not closing"),
        };

        assert_eq!(reason(Reason::Revoked), 1);
        assert_eq!(reason(Reason::Rotated), 2);
        assert_eq!(reason(Reason::Stopping), 3);
    }
}
