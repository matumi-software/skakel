//! An app's own gRPC service, `test.app.v1.Greeter`, written the way tonic's generated code is, so
//! the tests need no .proto file of their own: `Greet` answers who called, and `Watch` sends one
//! event and then stays open, as a call that pushes an app's state would. Both ends are here, the
//! service for the server and a small client for the tests.

#![allow(dead_code)]

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use skakel_server::ClientPrincipal;
use tonic::body::Body;
use tonic::codegen::http;
use tonic::server::NamedService;
use tonic::{Request, Response, Status};
use tonic_prost::ProstCodec;

/// The service's name, `<package>.<Service>`.
pub const NAME: &str = "test.app.v1.Greeter";
pub const GREET: &str = "/test.app.v1.Greeter/Greet";
pub const WATCH: &str = "/test.app.v1.Greeter/Watch";

#[derive(Clone, PartialEq, prost::Message)]
pub struct GreetRequest {
    #[prost(string, tag = "1")]
    pub text: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct GreetReply {
    #[prost(string, tag = "1")]
    pub text: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct WatchRequest {}

#[derive(Clone, PartialEq, prost::Message)]
pub struct WatchEvent {
    #[prost(string, tag = "1")]
    pub text: String,
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
type Events = Pin<Box<dyn tokio_stream::Stream<Item = Result<WatchEvent, Status>> + Send>>;

/// Who called, as Skakel's token check put it on the call.
fn caller<T>(request: &Request<T>) -> String {
    request
        .extensions()
        .get::<ClientPrincipal>()
        .map_or_else(|| "nobody".to_owned(), |p| p.0.client_id.clone())
}

struct Greet;

impl tonic::server::UnaryService<GreetRequest> for Greet {
    type Response = GreetReply;
    type Future = BoxFuture<Result<Response<GreetReply>, Status>>;

    fn call(&mut self, request: Request<GreetRequest>) -> Self::Future {
        Box::pin(async move {
            let who = caller(&request);
            Ok(Response::new(GreetReply {
                text: format!("{who}: {}", request.into_inner().text),
            }))
        })
    }
}

struct Watch;

impl tonic::server::ServerStreamingService<WatchRequest> for Watch {
    type Response = WatchEvent;
    type ResponseStream = Events;
    type Future = BoxFuture<Result<Response<Events>, Status>>;

    fn call(&mut self, request: Request<WatchRequest>) -> Self::Future {
        Box::pin(async move {
            let first = WatchEvent {
                text: format!("watching for {}", caller(&request)),
            };
            let events = tokio_stream::StreamExt::chain(
                tokio_stream::once(Ok(first)),
                tokio_stream::pending(),
            );
            Ok(Response::new(Box::pin(events) as Events))
        })
    }
}

/// The service, for [`skakel_server::SkakelServerBuilder::grpc_service`].
#[derive(Clone, Default)]
pub struct Greeter;

impl NamedService for Greeter {
    const NAME: &'static str = NAME;
}

impl tower_service::Service<http::Request<Body>> for Greeter {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = BoxFuture<Result<http::Response<Body>, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        match request.uri().path() {
            GREET => Box::pin(async move {
                let mut grpc = tonic::server::Grpc::new(ProstCodec::default());
                Ok(grpc.unary(Greet, request).await)
            }),
            WATCH => Box::pin(async move {
                let mut grpc = tonic::server::Grpc::new(ProstCodec::default());
                Ok(grpc.server_streaming(Watch, request).await)
            }),
            _ => Box::pin(async { Ok(Status::unimplemented("").into_http()) }),
        }
    }
}

/// Calls `Greet` over `connection`.
pub async fn greet<T>(connection: T, request: Request<GreetRequest>) -> Result<GreetReply, Status>
where
    T: tonic::client::GrpcService<Body>,
    T::Error: Into<tonic::codegen::StdError>,
    T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
    <T::ResponseBody as tonic::codegen::Body>::Error: Into<tonic::codegen::StdError> + Send,
{
    let mut grpc = tonic::client::Grpc::new(connection);
    grpc.ready()
        .await
        .map_err(|e| Status::unavailable(format!("not ready: {}", e.into())))?;
    grpc.unary(
        request,
        http::uri::PathAndQuery::from_static(GREET),
        ProstCodec::default(),
    )
    .await
    .map(Response::into_inner)
}

/// Calls `Watch` over `connection`.
pub async fn watch<T>(
    connection: T,
    request: Request<WatchRequest>,
) -> Result<tonic::Streaming<WatchEvent>, Status>
where
    T: tonic::client::GrpcService<Body>,
    T::Error: Into<tonic::codegen::StdError>,
    T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
    <T::ResponseBody as tonic::codegen::Body>::Error: Into<tonic::codegen::StdError> + Send,
{
    let mut grpc = tonic::client::Grpc::new(connection);
    grpc.ready()
        .await
        .map_err(|e| Status::unavailable(format!("not ready: {}", e.into())))?;
    grpc.server_streaming(
        request,
        http::uri::PathAndQuery::from_static(WATCH),
        ProstCodec::default(),
    )
    .await
    .map(Response::into_inner)
}

/// A service that claims a name in Skakel's own package, which a server refuses.
#[derive(Clone, Default)]
pub struct Impostor;

impl NamedService for Impostor {
    const NAME: &'static str = "skakel.v3.Impostor";
}

impl tower_service::Service<http::Request<Body>> for Impostor {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = BoxFuture<Result<http::Response<Body>, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _request: http::Request<Body>) -> Self::Future {
        Box::pin(async { Ok(Status::unimplemented("").into_http()) })
    }
}
