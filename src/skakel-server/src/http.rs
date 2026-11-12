//! The HTTPS side: info, pairing and tokens, the extractor an app's own endpoints take the bearer
//! token with, and the gate that limits the token and pairing paths before anything else reads the
//! request. Hello and the streams are gRPC in version 2.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Once};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{ConnectInfo, FromRequestParts, Path, Request, State};
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, PRAGMA};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use http_body_util::Limited;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::json;
use skakel_wire::pairing::{PairOpenRequest, PairRevealRequest, clean_client_name};
use skakel_wire::{
    ACCESS_TOKEN_LIFETIME, INFO_PATH, PAIR_PATH, PAIR_TOKEN_HEADER, PROBLEM_CONTENT_TYPE,
    SkakelInfo, TOKEN_PATH, VERSIONS,
};
use time::OffsetDateTime;

use crate::pairing::Reveal;
use crate::server::Shared;
use crate::tokens::Principal;
use crate::util::{MAX_CLIENT_NAME_LENGTH, bearer_token};

/// The largest body the token and pairing paths read.
pub(crate) const MAX_BODY_BYTES: usize = 4 * 1024;

/// A problem answer: `application/problem+json` with a `detail` a person can read.
pub(crate) fn problem(status: StatusCode, detail: &str) -> Response {
    let (kind, title) = match status.as_u16() {
        400 => (
            "https://tools.ietf.org/html/rfc9110#section-15.5.1",
            "Bad Request",
        ),
        401 => (
            "https://tools.ietf.org/html/rfc9110#section-15.5.2",
            "Unauthorized",
        ),
        404 => (
            "https://tools.ietf.org/html/rfc9110#section-15.5.5",
            "Not Found",
        ),
        409 => (
            "https://tools.ietf.org/html/rfc9110#section-15.5.10",
            "Conflict",
        ),
        413 => (
            "https://tools.ietf.org/html/rfc9110#section-15.5.14",
            "Content Too Large",
        ),
        422 => (
            "https://tools.ietf.org/html/rfc9110#section-15.5.21",
            "Unprocessable Content",
        ),
        429 => (
            "https://tools.ietf.org/html/rfc6585#section-4",
            "Too Many Requests",
        ),
        _ => ("about:blank", status.canonical_reason().unwrap_or("Error")),
    };
    let body = json!({ "type": kind, "title": title, "status": status.as_u16(), "detail": detail });
    (
        status,
        [(CONTENT_TYPE, HeaderValue::from_static(PROBLEM_CONTENT_TYPE))],
        body.to_string(),
    )
        .into_response()
}

fn unauthorized(detail: &str) -> Response {
    let mut response = problem(StatusCode::UNAUTHORIZED, detail);
    response.headers_mut().insert(
        "www-authenticate",
        HeaderValue::from_static("Bearer error=\"invalid_token\""),
    );
    response
}

/// The principal of the bearer token in a request's `Authorization` header.
pub(crate) fn authenticate_request(shared: &Shared, headers: &HeaderMap) -> Option<Principal> {
    shared.state.authenticate(bearer_token(headers)?)
}

/// The client behind a call's bearer token.
///
/// On an app's own HTTPS endpoints it is an axum extractor: the client, or a 401. On an app's own
/// gRPC services the server puts it in each call's extensions, after the token check, so a handler
/// reads it with `request.extensions().get::<ClientPrincipal>()`. Either way the token is checked
/// as the server's own calls check it, so one from a revoked client or an older generation is
/// refused.
///
/// A route that takes it must be given to [`SkakelServerBuilder::routes`](crate::SkakelServerBuilder::routes),
/// also when Skakel is mounted on the app's own router, because the server's state reaches only
/// the requests Skakel serves. A route on the app's own router instead gets a 500 with a problem
/// body that says so, and the first such request logs an error through the `log` crate.
#[derive(Debug, Clone)]
pub struct ClientPrincipal(pub Principal);

impl<S: Send + Sync> FromRequestParts<S> for ClientPrincipal {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let Some(shared) = parts.extensions.get::<Arc<Shared>>().cloned() else {
            return Err(outside_skakel(parts.uri.path()));
        };
        authenticate_request(&shared, &parts.headers)
            .map(Self)
            .ok_or_else(|| unauthorized("Send a current bearer token. This one is missing or has expired, or the client was revoked or its secret rotated since it was issued."))
    }
}

/// The answer when [`ClientPrincipal`] is taken on a request Skakel did not serve, so there is no
/// server to check the token against. There is also no server to tell with an event, so it logs,
/// once per process rather than once per request.
fn outside_skakel(path: &str) -> Response {
    static LOGGED: Once = Once::new();
    LOGGED.call_once(|| {
        log::error!(
            "The route {path:?} takes ClientPrincipal but is not served by Skakel. Give it to SkakelServerBuilder::routes instead of the app's own router."
        );
    });
    problem(
        StatusCode::INTERNAL_SERVER_ERROR,
        "This route needs the client behind the bearer token, but it is not served by Skakel. The app must give it to SkakelServerBuilder::routes rather than mount it on its own router.",
    )
}

/// The server's own routes, with the gate in front.
pub(crate) fn router(shared: Arc<Shared>) -> Router {
    Router::new()
        .route(INFO_PATH, get(info))
        .route(PAIR_PATH, post(pair_open))
        .route(&format!("{PAIR_PATH}/{{id}}/reveal"), post(pair_reveal))
        .route(
            &format!("{PAIR_PATH}/{{id}}"),
            get(pair_poll).delete(pair_withdraw),
        )
        .route(TOKEN_PATH, post(token))
        .with_state(shared)
}

/// Puts the limits and the layer around `router`: every request carries the server's state for
/// [`ClientPrincipal`], and the token and pairing paths are limited per address and capped in
/// body size before routing reads anything.
pub(crate) fn guard(router: Router, shared: Arc<Shared>) -> Router {
    router.layer(middleware::from_fn_with_state(shared, gate))
}

async fn gate(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    mut request: Request,
    next: Next,
) -> Response {
    request.extensions_mut().insert(shared.clone());
    let path = request.uri().path().to_ascii_lowercase();
    let on = |base: &str| {
        path == base.to_ascii_lowercase()
            || path.starts_with(&format!("{}/", base.to_ascii_lowercase()))
    };
    let (is_token, is_pair) = (on(TOKEN_PATH), on(PAIR_PATH));
    if !is_token && !is_pair {
        return next.run(request).await;
    }
    let allowed = if is_token {
        shared.limits.try_token(remote.ip())
    } else {
        shared.limits.try_pair(remote.ip())
    };
    if !allowed {
        return problem(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests from this address. Wait a minute and try again.",
        );
    }
    let declared = request
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if declared.is_some_and(|length| length > MAX_BODY_BYTES as u64) {
        return problem(
            StatusCode::PAYLOAD_TOO_LARGE,
            &format!("The body is over {MAX_BODY_BYTES} bytes."),
        );
    }
    // A body sent without a length is cut off once it passes the cap.
    let (parts, body) = request.into_parts();
    let body = Body::new(TimedBody::new(Limited::new(body, MAX_BODY_BYTES)));
    next.run(Request::from_parts(parts, body)).await
}

/// How long a client has to send the whole body of a token or pairing request, which is at most
/// [`MAX_BODY_BYTES`]. A client that sends the headers and then stops would otherwise hold the
/// connection for as long as it likes.
pub(crate) const BODY_TIMEOUT: Duration = Duration::from_secs(10);

/// A request body that fails when it has not been read to its end within [`BODY_TIMEOUT`] of the
/// request arriving.
struct TimedBody<B> {
    inner: B,
    deadline: Pin<Box<tokio::time::Sleep>>,
}

impl<B> TimedBody<B> {
    fn new(inner: B) -> Self {
        Self {
            inner,
            deadline: Box::pin(tokio::time::sleep(BODY_TIMEOUT)),
        }
    }
}

impl<B> http_body::Body for TimedBody<B>
where
    B: http_body::Body + Unpin,
    B::Error: Into<axum::BoxError>,
{
    type Data = B::Data;
    type Error = axum::BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        if let Poll::Ready(frame) = Pin::new(&mut self.inner).poll_frame(cx) {
            return Poll::Ready(frame.map(|frame| frame.map_err(Into::into)));
        }
        if self.deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Some(Err("The body did not arrive in time.".into())));
        }
        Poll::Pending
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

async fn info(State(shared): State<Arc<Shared>>) -> Json<SkakelInfo> {
    Json(SkakelInfo {
        name: shared.name.clone(),
        app: shared.app.clone(),
        versions: VERSIONS.to_vec(),
    })
}

fn has_json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            let media = value
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            media == "application/json"
                || (media.starts_with("application/") && media.ends_with("+json"))
        })
}

/// The JSON body, or `None` for anything else: no JSON content type, too long, not JSON.
async fn read_json<T: DeserializeOwned>(headers: &HeaderMap, body: Body) -> Option<T> {
    if !has_json_content_type(headers) {
        return None;
    }
    let bytes = to_bytes(body, MAX_BODY_BYTES).await.ok()?;
    serde_json::from_slice(&bytes).ok()
}

async fn pair_open(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(request) = read_json::<PairOpenRequest>(&headers, body).await else {
        return problem(
            StatusCode::BAD_REQUEST,
            "Send the client's name and commitment as JSON.",
        );
    };
    // The code is made from the name as the client sent it; the server keeps it cleaned.
    let sent_name = request.client_name.as_deref().unwrap_or("");
    let name = clean_client_name(sent_name);
    if name.is_empty() || name.chars().count() > MAX_CLIENT_NAME_LENGTH {
        return problem(
            StatusCode::BAD_REQUEST,
            &format!("Give the client a name of 1 to {MAX_CLIENT_NAME_LENGTH} characters."),
        );
    }
    let commitment = match request.commitment {
        Some(commitment)
            if commitment.len() == 64 && commitment.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            commitment
        }
        _ => {
            return problem(
                StatusCode::BAD_REQUEST,
                "The commitment must be the 64 hex digits of a SHA-256 hash.",
            );
        }
    };
    match shared
        .pairing
        .open(sent_name, &commitment, remote.ip())
        .await
    {
        Some(opened) => Json(opened).into_response(),
        None => problem(
            StatusCode::TOO_MANY_REQUESTS,
            "This server is taking no more pairing requests from here for now. Try again in a few minutes.",
        ),
    }
}

fn no_such_request() -> Response {
    problem(
        StatusCode::NOT_FOUND,
        "There is no such pairing request waiting, or the poll token is wrong.",
    )
}

async fn pair_reveal(
    State(shared): State<Arc<Shared>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let nonce = read_json::<PairRevealRequest>(&headers, body)
        .await
        .and_then(|request| request.client_nonce)
        .filter(|nonce| !nonce.is_empty());
    let Some(nonce) = nonce else {
        return no_such_request();
    };
    match shared.pairing.reveal(&id, &nonce).await {
        Reveal::Revealed => StatusCode::NO_CONTENT.into_response(),
        Reveal::Full => problem(
            StatusCode::TOO_MANY_REQUESTS,
            "This server has as many pairing requests waiting as a person can look at. Try again in a few minutes.",
        ),
        Reveal::NotFound => no_such_request(),
    }
}

fn poll_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(PAIR_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
}

async fn pair_poll(
    State(shared): State<Arc<Shared>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    match shared.pairing.poll(&id, poll_token(&headers)).await {
        Some(poll) => Json(poll).into_response(),
        None => no_such_request(),
    }
}

async fn pair_withdraw(
    State(shared): State<Arc<Shared>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if shared.pairing.withdraw(&id, poll_token(&headers)).await {
        StatusCode::NO_CONTENT.into_response()
    } else {
        no_such_request()
    }
}

#[derive(Deserialize, Default)]
struct TokenForm {
    grant_type: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    let body = json!({ "error": error, "error_description": description });
    (
        status,
        [(CONTENT_TYPE, "application/json;charset=UTF-8")],
        body.to_string(),
    )
        .into_response()
}

fn invalid_client() -> Response {
    oauth_error(
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        "The client ID or secret is wrong, or the client was revoked.",
    )
}

/// The client id and secret from an `Authorization: Basic` header, form-decoded as RFC 6749 says.
fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, encoded) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = String::from_utf8(STANDARD.decode(encoded.trim()).ok()?).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    // Each part is one form-encoded value, so a literal `&` (which would start a second field) is
    // not one; it has to be written `%26`.
    let decode = |text: &str| -> Option<String> {
        if text.contains('&') {
            return None;
        }
        let pairs: Vec<(String, String)> = serde_urlencoded::from_str(&format!("v={text}")).ok()?;
        let mut pairs = pairs.into_iter();
        let (_, value) = pairs.next()?;
        pairs.next().is_none().then_some(value)
    };
    Some((decode(id)?, decode(secret)?))
}

async fn token(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let is_form = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        });
    if !is_form {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The token request must be an application/x-www-form-urlencoded POST.",
        );
    }
    let Ok(bytes) = to_bytes(body, MAX_BODY_BYTES).await else {
        return problem(
            StatusCode::BAD_REQUEST,
            "The request body could not be read, or it is over the limit.",
        );
    };
    let Ok(form) = serde_urlencoded::from_bytes::<TokenForm>(&bytes) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The request body is not a form.",
        );
    };
    if form.grant_type.as_deref() != Some("client_credentials") {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "Only the client_credentials grant is supported.",
        );
    }
    let (client_id, client_secret) = match (form.client_id, form.client_secret) {
        (Some(id), Some(secret)) => (id, secret),
        _ => basic_credentials(&headers).unwrap_or_default(),
    };
    // Only registered clients are counted, so made-up ids cannot fill the limiter.
    if client_id.is_empty() || client_secret.is_empty() || shared.state.find(&client_id).is_none() {
        return invalid_client();
    }
    if shared.limits.too_many_failures(&client_id, remote.ip()) {
        return problem(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many wrong secrets for this client from this address. Wait a minute and try again.",
        );
    }
    let Some(generation) = shared.state.validate(&client_id, &client_secret) else {
        shared.limits.count_failure(&client_id, remote.ip());
        return invalid_client();
    };
    let (access_token, expires_at) =
        match shared
            .state
            .issue_token_for(&client_id, generation, shared.token_lifetime)
        {
            Ok(token) => token,
            Err(error) => {
                // Nothing safe to make a token with: refuse, as for any server fault.
                log::error!("A token was refused: {error}");
                return problem(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "The server could not make a token. Try again later.",
                );
            }
        };
    let expires_in = (expires_at - OffsetDateTime::now_utc())
        .whole_seconds()
        .clamp(0, ACCESS_TOKEN_LIFETIME.as_secs() as i64);
    let body =
        json!({ "access_token": access_token, "token_type": "Bearer", "expires_in": expires_in });
    (
        StatusCode::OK,
        [
            (CONTENT_TYPE, "application/json;charset=UTF-8"),
            (CACHE_CONTROL, "no-store"),
            (PRAGMA, "no-cache"),
        ],
        body.to_string(),
    )
        .into_response()
}

/// Whether bytes are what a client would send to start a TLS handshake.
pub(crate) fn looks_like_tls(first_byte: u8) -> bool {
    first_byte == 0x16
}

/// What a client that spoke plain HTTP to the TLS port is told.
pub(crate) fn plain_http_answer() -> Bytes {
    let body = json!({
        "type": "https://tools.ietf.org/html/rfc9110#section-15.5.1",
        "title": "Bad Request",
        "status": 400,
        "detail": "This is a Skakel server. Talk to it over HTTPS, pinned to the server's certificate.",
    })
    .to_string();
    Bytes::from(format!(
        "HTTP/1.1 400 Bad Request\r\ncontent-type: {PROBLEM_CONTENT_TYPE}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic(text: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", STANDARD.encode(text))).unwrap(),
        );
        headers
    }

    #[test]
    fn basic_credentials_are_the_form_decoded_id_and_secret() {
        assert_eq!(
            basic_credentials(&basic("client-1:s3cret")),
            Some(("client-1".into(), "s3cret".into()))
        );
        assert_eq!(
            basic_credentials(&basic("client-1:p%40ss+word")),
            Some(("client-1".into(), "p@ss word".into()))
        );
    }

    #[test]
    fn basic_credentials_with_anything_after_the_secret_are_refused() {
        assert_eq!(basic_credentials(&basic("client-1:SECRET&junk=1")), None);
        assert_eq!(basic_credentials(&basic("client-1&x:SECRET")), None);
        assert_eq!(basic_credentials(&basic("client-1:SECRET&")), None);
    }

    #[test]
    fn basic_credentials_without_a_colon_or_a_basic_scheme_are_refused() {
        assert_eq!(basic_credentials(&basic("client-1")), None);
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer abc"));
        assert_eq!(basic_credentials(&headers), None);
    }
}

#[cfg(test)]
mod properties {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// An id and secret are read back from a Basic header, whatever characters they hold, once
        /// form-encoded as RFC 6749 says.
        #[test]
        fn basic_credentials_read_back(id in "[^:]{1,30}", secret in ".{1,40}") {
            let encode = |text: &str| serde_urlencoded::to_string([("v", text)]).unwrap()[2..].to_owned();
            let raw = format!("{}:{}", encode(&id), encode(&secret));
            let mut headers = HeaderMap::new();
            headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Basic {}", STANDARD.encode(raw))).unwrap());
            prop_assert_eq!(basic_credentials(&headers), Some((id, secret)));
        }

        /// Any header value is read as credentials or refused, never a panic.
        #[test]
        fn a_basic_header_is_read_or_refused(value in proptest::collection::vec(32u8..127, 0..120)) {
            let mut headers = HeaderMap::new();
            headers.insert(AUTHORIZATION, HeaderValue::from_bytes(&value).unwrap());
            let _ = basic_credentials(&headers);
        }
    }
}
