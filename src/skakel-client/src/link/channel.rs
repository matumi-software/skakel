//! The app's own gRPC calls over the control connection.

use super::*;

/// The app's own gRPC calls over a link's control connection, for tonic's generated clients. See
/// [`Link::channel`]. Cloning it is cheap; every clone follows the link's current connection.
#[derive(Clone)]
pub struct LinkChannel {
    pub(super) inner: Arc<Inner>,
}

impl std::fmt::Debug for LinkChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkChannel").finish_non_exhaustive()
    }
}

impl tower_service::Service<tonic::codegen::http::Request<Body>> for LinkChannel {
    type Response = tonic::codegen::http::Response<Body>;
    type Error = Status;
    type Future = grpc::BoxFuture<std::result::Result<Self::Response, Status>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::result::Result<(), Status>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut request: tonic::codegen::http::Request<Body>) -> Self::Future {
        let inner = self.inner.clone();
        Box::pin(async move {
            let connection = inner.control.borrow().clone();
            let Some(connection) = connection.filter(|c| !c.is_closed()) else {
                return Err(Status::unavailable(
                    Failure::of(FailureKind::NotConnected).message(),
                ));
            };
            let token = inner.tokens.get().await.map_err(|error| {
                let message = error.failure().message().to_owned();
                if matches!(
                    error.kind(),
                    FailureKind::Unreachable | FailureKind::ConnectionLost
                ) {
                    Status::unavailable(message)
                } else {
                    Status::unauthenticated(message)
                }
            })?;
            let mut value: tonic::codegen::http::HeaderValue = format!("Bearer {}", token.value)
                .parse()
                .map_err(|_| Status::internal("The token is not a header value."))?;
            value.set_sensitive(true);
            request.headers_mut().insert("authorization", value);
            let mut service = connection.service();
            std::future::poll_fn(|cx| tower_service::Service::poll_ready(&mut service, cx)).await?;
            let response = tower_service::Service::call(&mut service, request).await?;
            // A refusal comes as the whole answer, before any message.
            if Status::from_header_map(response.headers()).is_some_and(|s| is_token_refused(&s)) {
                inner.tokens.forget(&token.value).await;
            }
            Ok(response)
        })
    }
}
