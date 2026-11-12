//! Gets client-credentials access tokens from one server and reuses each until shortly before it
//! expires. One per link, shared by the control channel, the streams and the app's own calls.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use reqwest::Url;
use serde::Deserialize;
use skakel_protocol::{ACCESS_TOKEN_LIFETIME, TOKEN_PATH};
use tokio::sync::Mutex;

use crate::clock::{Clock, since};
use crate::failure::{Error, TokenRequestError, bad_answer};
use crate::http;
use crate::pins::Credentials;

/// A token is renewed this long before it expires, so one handed out still has time to be used.
pub(crate) const RENEW_BEFORE: Duration = Duration::from_secs(60);

/// The shortest lifetime a token is taken to have, whatever the server says, so a server cannot set
/// off a stream of renewals.
pub(crate) const MIN_LIFETIME: Duration = Duration::from_secs(2 * 60);

/// The longest lifetime a token is taken to have: the protocol's 30 minutes.
pub(crate) const MAX_LIFETIME: Duration = ACCESS_TOKEN_LIFETIME;

/// A token and when it expires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Token {
    pub value: String,
    pub expires_at: SystemTime,
}

pub(crate) struct TokenClient {
    http: reqwest::Client,
    server: Box<dyn Fn() -> Url + Send + Sync>,
    credentials: Credentials,
    clock: Arc<dyn Clock>,
    timeout: Duration,
    cached: Mutex<Option<Token>>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    expires_in: Option<i64>,
    error: Option<String>,
}

impl TokenClient {
    pub fn new(
        http: reqwest::Client,
        server: impl Fn() -> Url + Send + Sync + 'static,
        credentials: Credentials,
        clock: Arc<dyn Clock>,
        timeout: Duration,
    ) -> Self {
        Self {
            http,
            server: Box::new(server),
            credentials,
            clock,
            timeout,
            cached: Mutex::new(None),
        }
    }

    /// A token that has at least a minute left, and when it expires.
    pub async fn get(&self) -> Result<Token, Error> {
        let mut cached = self.cached.lock().await;
        if let Some(token) = cached.as_ref()
            && since(token.expires_at, self.clock.now()) > RENEW_BEFORE
        {
            return Ok(token.clone());
        }

        let url = (self.server)()
            .join(TOKEN_PATH)
            .map_err(Error::from_cause)?;
        let response = self
            .http
            .post(url)
            .timeout(self.timeout)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", self.credentials.client_id.as_str()),
                ("client_secret", self.credentials.client_secret.as_str()),
            ])
            .send()
            .await
            .map_err(Error::from_cause)?;
        let status = response.status();
        let body = http::read_limited(response).await?;
        // The JSON body, or nothing when there is none or it is not JSON, such as a proxy's error page.
        let parsed: Option<TokenResponse> = serde_json::from_slice(&body).ok();
        if !status.is_success() {
            let error = parsed
                .and_then(|p| p.error)
                .unwrap_or_else(|| format!("http_{}", status.as_u16()));
            return Err(Error::from_cause(TokenRequestError {
                error,
                status: status.as_u16(),
            }));
        }
        let Some(TokenResponse {
            access_token: Some(value),
            expires_in,
            ..
        }) = parsed.filter(|p| p.access_token.as_deref().is_some_and(|t| !t.is_empty()))
        else {
            return Err(bad_answer("The token answer has no access token."));
        };

        // It goes in a header on every call, so one that cannot is refused here, once, not dropped
        // later without a word.
        if reqwest::header::HeaderValue::from_str(&format!("Bearer {value}")).is_err() {
            return Err(bad_answer("The access token cannot be sent in a header."));
        }
        let fresh = Token {
            value,
            expires_at: self.clock.now() + lifetime(expires_in),
        };
        *cached = Some(fresh.clone());
        Ok(fresh)
    }

    /// Drops the cached token, as after the server refused it, unless a newer one replaced it
    /// already.
    pub async fn forget(&self, token: &str) {
        let mut cached = self.cached.lock().await;
        if cached.as_ref().is_some_and(|t| t.value == token) {
            *cached = None;
        }
    }
}

/// The server's `expires_in`, held to 2 to 30 minutes; five minutes when it gave none.
pub(crate) fn lifetime(expires_in: Option<i64>) -> Duration {
    let seconds = expires_in
        .unwrap_or(300)
        .clamp(MIN_LIFETIME.as_secs() as i64, MAX_LIFETIME.as_secs() as i64);
    Duration::from_secs(seconds as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifetime_is_held_to_two_to_thirty_minutes() {
        assert_eq!(lifetime(Some(1800)), Duration::from_secs(1800));
        assert_eq!(lifetime(Some(10)), Duration::from_secs(120));
        assert_eq!(lifetime(Some(-5)), Duration::from_secs(120));
        assert_eq!(lifetime(Some(86_400)), Duration::from_secs(1800));
        assert_eq!(lifetime(None), Duration::from_secs(300));
    }
}
