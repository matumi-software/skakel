//! Plain HTTPS over the pinned connector: one request, one TCP connection, one TLS handshake that
//! trusts the pins and nothing else, HTTP/1.1, the whole answer read up to a limit, then the
//! connection is gone. No pool, no redirect, no proxy: a Skakel server is on the local network, a
//! system proxy would see every address and could not reach most of them, and a connection kept for
//! another request could outlive a pin the link has since dropped.

use std::sync::Arc;
use std::time::Duration;

use http::header::{CONTENT_LENGTH, CONTENT_TYPE, HOST, HeaderName, HeaderValue};
use http::{HeaderMap, Method, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::TokioIo;
use prost::bytes::Bytes;
use serde::Serialize;
use serde::de::DeserializeOwned;
use url::Url;

use crate::failure::{Error, FailureKind, StatusError, bad_answer};
use crate::http::{MAX_RESPONSE_BYTES, PinsFn, Presented, connect_tls, tls_config};
use crate::pins::Pins;

/// How long a request may take unless the caller says otherwise.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Stops the task that drives a connection when the request is over.
struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// An HTTPS client that trusts the pins it reads at each handshake. Cheap to clone.
#[derive(Clone)]
pub(crate) struct HttpClient {
    config: Arc<rustls::ClientConfig>,
}

impl std::fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpClient").finish_non_exhaustive()
    }
}

impl HttpClient {
    /// A client over the pins. `presented`, when given, is told the fingerprint of each certificate
    /// a handshake trusted.
    pub(crate) fn new(pins: PinsFn, presented: Option<Presented>) -> Self {
        let mut config = tls_config(pins, presented);
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        // A resumed session shows no certificate and skips the check of the pins, which a link
        // that dropped a pin must not allow.
        config.resumption = rustls::client::Resumption::disabled();
        Self {
            config: Arc::new(config),
        }
    }

    /// A client pinned to fixed pins.
    pub(crate) fn pinned(pins: Pins) -> Self {
        Self::new(Arc::new(move || pins.clone()), None)
    }

    pub(crate) fn get(&self, url: Url) -> RequestBuilder {
        self.request(Method::GET, url)
    }

    pub(crate) fn post(&self, url: Url) -> RequestBuilder {
        self.request(Method::POST, url)
    }

    pub(crate) fn delete(&self, url: Url) -> RequestBuilder {
        self.request(Method::DELETE, url)
    }

    pub(crate) fn request(&self, method: Method, url: Url) -> RequestBuilder {
        RequestBuilder {
            client: Some(self.clone()),
            method,
            url,
            headers: HeaderMap::new(),
            body: Bytes::new(),
            timeout: DEFAULT_TIMEOUT,
            max_response: MAX_RESPONSE_BYTES,
            invalid: None,
        }
    }
}

/// A request to one of a server's HTTPS endpoints, as the app builds it in
/// [`Link::request`](crate::Link::request): headers and a body. The method, the address and the
/// token are the link's.
#[derive(Debug)]
pub struct RequestBuilder {
    client: Option<HttpClient>,
    method: Method,
    url: Url,
    headers: HeaderMap,
    body: Bytes,
    timeout: Duration,
    max_response: usize,
    invalid: Option<String>,
}

impl RequestBuilder {
    /// Adds a header. A name or value that cannot be one fails the request when it is sent.
    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        match (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            (Ok(name), Ok(value)) => {
                self.headers.append(name, value);
            }
            _ => self.invalid = Some(format!("The header {name:?} is not valid.")),
        }
        self
    }

    /// Sets the body.
    #[must_use]
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }

    /// Sets the body to `value` as JSON, and the content type with it.
    #[must_use]
    pub fn json<T: Serialize + ?Sized>(mut self, value: &T) -> Self {
        match serde_json::to_vec(value) {
            Ok(bytes) => {
                self.body = bytes.into();
                self.headers
                    .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            }
            Err(error) => self.invalid = Some(error.to_string()),
        }
        self
    }

    /// Sets the body to the pairs as a form, and the content type with it.
    #[must_use]
    pub(crate) fn form(mut self, pairs: &[(&str, &str)]) -> Self {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        self.body = body.into();
        self.headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        self
    }

    /// How long the whole request may take, connecting and reading the answer included.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The most bytes of the answer that are read.
    #[must_use]
    pub(crate) fn max_response(mut self, bytes: usize) -> Self {
        self.max_response = bytes;
        self
    }

    /// Signs the request with a bearer token, kept out of logs.
    #[must_use]
    pub(crate) fn bearer(mut self, token: &str) -> Self {
        match HeaderValue::from_str(&format!("Bearer {token}")) {
            Ok(mut value) => {
                value.set_sensitive(true);
                self.headers.insert(http::header::AUTHORIZATION, value);
            }
            Err(_) => self.invalid = Some("The token is not a header value.".to_owned()),
        }
        self
    }

    /// A request for a link: the client the link made, and the method and address it chose.
    pub(crate) fn for_link(method: Method, url: Url) -> Self {
        Self {
            client: None,
            method,
            url,
            headers: HeaderMap::new(),
            body: Bytes::new(),
            timeout: DEFAULT_TIMEOUT,
            max_response: MAX_RESPONSE_BYTES,
            invalid: None,
        }
    }

    /// The same request, to be sent by `client`.
    pub(crate) fn with_client(mut self, client: &HttpClient) -> Self {
        self.client = Some(client.clone());
        self
    }

    /// Sends it and reads the answer.
    pub(crate) async fn send(self) -> Result<Response, Error> {
        if let Some(problem) = self.invalid {
            return Err(Error::caused(
                FailureKind::InvalidRequest,
                crate::failure::BadAnswer(problem),
            ));
        }
        let Some(client) = self.client else {
            return Err(Error::of(FailureKind::InvalidRequest));
        };
        let timeout = self.timeout;
        let work = exchange(
            client,
            self.method,
            self.url,
            self.headers,
            self.body,
            self.max_response,
        );
        tokio::time::timeout(timeout, work)
            .await
            .map_err(Error::from_cause)?
    }
}

async fn exchange(
    client: HttpClient,
    method: Method,
    url: Url,
    mut headers: HeaderMap,
    body: Bytes,
    max_response: usize,
) -> Result<Response, Error> {
    let tls = connect_tls(&url, client.config.clone()).await?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .map_err(Error::from_cause)?;
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let _guard = AbortOnDrop(driver.abort_handle());

    let host = match url.port() {
        Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
        None => url.host_str().unwrap_or_default().to_owned(),
    };
    headers.insert(
        HOST,
        HeaderValue::from_str(&host).map_err(Error::from_cause)?,
    );
    headers.insert(http::header::CONNECTION, HeaderValue::from_static("close"));
    headers.remove(CONTENT_LENGTH);
    let target = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    };
    let mut request = http::Request::builder().method(method).uri(target);
    *request
        .headers_mut()
        .ok_or_else(|| Error::of(FailureKind::InvalidRequest))? = headers;
    let request = request.body(Full::new(body)).map_err(Error::from_cause)?;

    let response = sender
        .send_request(request)
        .await
        .map_err(Error::from_cause)?;
    let (parts, incoming) = response.into_parts();
    if parts
        .headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|length| length > max_response as u64)
    {
        return Err(bad_answer("The answer is longer than the client reads."));
    }
    let collected = Limited::new(incoming, max_response)
        .collect()
        .await
        .map_err(|error| {
            if error.is::<http_body_util::LengthLimitError>() {
                bad_answer("The answer is longer than the client reads.")
            } else {
                Error::from_cause(error)
            }
        })?;
    Ok(Response {
        status: parts.status,
        headers: parts.headers,
        body: collected.to_bytes(),
    })
}

/// A server's answer to a plain HTTPS request, read whole.
#[derive(Debug, Clone)]
pub struct Response {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Response {
    /// The status.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// The body.
    pub fn bytes(&self) -> &Bytes {
        &self.body
    }

    /// The body as text; bytes that are not UTF-8 are replaced.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The body as JSON.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T, Error> {
        serde_json::from_slice(&self.body).map_err(Error::from_cause)
    }

    /// An error unless the status is 2xx.
    pub(crate) fn ensure_success(&self) -> Result<(), Error> {
        if self.status.is_success() {
            Ok(())
        } else {
            Err(Error::from_cause(StatusError(self.status.as_u16())))
        }
    }

    /// The body of a successful answer as JSON.
    pub(crate) fn read_json<T: DeserializeOwned>(&self) -> Result<T, Error> {
        self.ensure_success()?;
        self.json()
    }
}
