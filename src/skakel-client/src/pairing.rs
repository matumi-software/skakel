//! Pairing with a server, so the client gets its credentials without anyone typing a secret.
//!
//! Opens a request over HTTPS pinned to the fingerprint discovery announced, with a commitment to a
//! nonce, reveals the nonce, and gives the eight-digit [`code`](PairingClient::code) to show. A person
//! types it on the server; [`wait`](PairingClient::wait) polls until they did and hands the
//! credentials to the app, which decides where to keep them.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant, SystemTime};

use ::http::StatusCode;
use skakel_wire::pairing::{
    PairOpenRequest, PairOpened, PairPoll, PairRevealRequest, PairState, RandomError, commit,
    compute, new_nonce,
};
use skakel_wire::{PAIR_PATH, PAIR_TOKEN_HEADER};
use url::Url;
use zeroize::Zeroize;

use crate::clock::{Clock, since, wall_since};
use crate::failure::{Error, FailureKind, Result, bad_answer};
use crate::http::{self, base_address};
use crate::info::{read_info_with, require_version};
use crate::options::ClientOptions;
use crate::pins::{Credentials, Pins};
use crate::request::HttpClient;

/// How long past its expiry a request is still polled, for a clock that differs from the server's.
const EXPIRY_GRACE: Duration = Duration::from_secs(30);

/// The longest a request is waited for, whatever the server says: the five minutes after which the
/// protocol has it expire.
pub const MAX_WAIT: Duration = Duration::from_secs(5 * 60);

/// The longest request ID or poll token taken from a server. The server's own are far shorter.
const MAX_ID_LENGTH: usize = 128;

/// The longest a client name is, in Unicode scalar values as the server counts them.
const MAX_CLIENT_NAME_LENGTH: usize = 80;

/// Why a pairing request could not be opened.
#[derive(Debug)]
#[non_exhaustive]
pub enum PairingError {
    /// The client's name is empty once trimmed, or longer than 80 characters.
    InvalidClientName,
    /// The operating system had no random numbers to make the pairing nonce from.
    NoRandomness(RandomError),
    /// The server could not be reached, presented another certificate, speaks no common version, or
    /// refused the request.
    Failed(Error),
}

impl fmt::Display for PairingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidClientName => f.write_str("Give the client a name of 1 to 80 characters."),
            Self::NoRandomness(error) => error.fmt(f),
            Self::Failed(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for PairingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Failed(error) => Some(error),
            Self::NoRandomness(error) => Some(error),
            Self::InvalidClientName => None,
        }
    }
}

impl From<Error> for PairingError {
    fn from(error: Error) -> Self {
        Self::Failed(error)
    }
}

/// How many polls in a row may fail on the network before the wait gives up.
const MAX_FAILED_POLLS: u32 = 10;

const WAITING: u8 = 0;
const FINISHED: u8 = 1;

/// An open pairing request. Dropping one that is still waiting withdraws it, in the background; use
/// [`withdraw`](Self::withdraw) to wait for that.
pub struct PairingClient {
    http: HttpClient,
    address: Url,
    pins: Pins,
    server_name: String,
    code: String,
    expires_at: SystemTime,
    /// When the wait ends, on the monotonic clock: `expires_at` as the time left when it was
    /// worked out.
    deadline: Instant,
    request_id: String,
    poll_token: String,
    clock: Arc<dyn Clock>,
    poll_interval: Duration,
    request_timeout: Duration,
    state: Arc<AtomicU8>,
}

impl fmt::Debug for PairingClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingClient")
            .field("address", &self.address.as_str())
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

impl PairingClient {
    /// Opens a pairing request: checks the server speaks this client's protocol, sends the
    /// commitment, reveals the nonce, and works out the code.
    ///
    /// - `address` is the server's HTTPS address, from discovery.
    /// - `fingerprint` is the certificate's fingerprint, from discovery. It is pinned from here on,
    ///   and goes into the code.
    /// - `client_name` is what the server's people see this client as: 1 to 80 characters, such as
    ///   the machine's name.
    pub async fn open(
        address: &Url,
        fingerprint: &str,
        client_name: &str,
        options: &ClientOptions,
    ) -> Result<Self, PairingError> {
        let name = client_name.trim();
        if name.is_empty() || name.chars().count() > MAX_CLIENT_NAME_LENGTH {
            return Err(PairingError::InvalidClientName);
        }
        let server = base_address(address)?;
        let pins = Pins::new(fingerprint)
            .map_err(|e| Error::caused(FailureKind::CertificateMismatch, e))?;
        let nonce = new_nonce().map_err(PairingError::NoRandomness)?;
        let client = HttpClient::pinned(pins.clone());
        let timeout = options.request_timeout;
        let opened = async {
            let info = read_info_with(&client, &server, timeout).await?;
            require_version(&info.versions)?;

            let open = client
                .post(server.join(PAIR_PATH).map_err(Error::from_cause)?)
                .timeout(timeout)
                .json(&PairOpenRequest {
                    client_name: Some(name.to_owned()),
                    commitment: Some(commit(&nonce)),
                })
                .send()
                .await?;
            let opened: PairOpened = open.read_json()?;
            if opened.server_nonce.is_empty()
                || !is_id(&opened.request_id)
                || !is_id(&opened.poll_token)
            {
                return Err(bad_answer(
                    "The pairing answer is missing the request, the nonce or the poll token, or they are not short printable text.",
                ));
            }

            // The name goes into the code exactly as it was sent in the opening call.
            let code = compute(pins.fingerprint(), name, &nonce, &opened.server_nonce)
                .ok_or_else(|| Error::of(FailureKind::CertificateMismatch))?;
            let now = options.clock.now();
            // By this client's clock: never later than five minutes from now, however far off the
            // server's answer is.
            let expires_at = SystemTime::from(opened.expires_at).min(now + MAX_WAIT);
            let deadline = options.clock.instant() + wall_since(expires_at, now);
            let pairing = PairingClient {
                http: client.clone(),
                address: server.clone(),
                pins: pins.clone(),
                server_name: info.name.clone(),
                code,
                expires_at,
                deadline,
                request_id: opened.request_id,
                poll_token: opened.poll_token,
                clock: options.clock.clone(),
                poll_interval: Duration::from_secs(2),
                request_timeout: timeout,
                state: Arc::new(AtomicU8::new(WAITING)),
            };

            let revealed = client
                .post(pair_url(&server, &pairing.request_id, Some("reveal"))?)
                .timeout(timeout)
                .json(&PairRevealRequest {
                    client_nonce: Some(nonce),
                })
                .send()
                .await;
            let revealed = match revealed {
                Ok(revealed) if revealed.status() == StatusCode::NOT_FOUND => {
                    // Dropped: it took too long to reveal, or the server restarted.
                    pairing.withdraw().await;
                    return Err(Error::of(FailureKind::PairingExpired));
                }
                Ok(revealed) => revealed.ensure_success(),
                Err(error) => Err(error),
            };
            if let Err(error) = revealed {
                pairing.withdraw().await;
                return Err(error);
            }
            log::info!("Waiting for the code to be typed on {}", pairing.server_name);
            Ok(pairing)
        }
        .await;
        opened.map_err(|error| {
            log::warn!(
                "Pairing with {} failed: {error:?}",
                http::authority(&server)
            );
            PairingError::Failed(error)
        })
    }

    /// The server's address.
    pub fn address(&self) -> &Url {
        &self.address
    }

    /// The pinned certificate. The app keeps it with the credentials.
    pub fn pins(&self) -> &Pins {
        &self.pins
    }

    /// The server's name, from its info.
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// The eight-digit code to show. The person types it on the server.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// When the request runs out: the server's word for it, but never more than five minutes after
    /// it opened.
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }

    /// How often a waiting request is polled: every two seconds unless set. The server allows once
    /// a second.
    pub fn set_poll_interval(&mut self, interval: Duration) {
        self.poll_interval = interval;
    }

    /// Polls until the person typed the code on the server, and returns the credentials. They are
    /// handed over once: keep them before anything else.
    ///
    /// Dropping the future stops waiting; the request stays open until it is withdrawn or dropped.
    /// Fails with [`FailureKind::PairingDenied`] when the server refused the request,
    /// [`FailureKind::PairingExpired`] when it ran out, or another kind when the server could not be
    /// reached.
    pub async fn wait(&self) -> Result<Credentials> {
        if self.state.load(Ordering::SeqCst) != WAITING {
            return Err(Error::of(FailureKind::PairingExpired));
        }
        let result = self.poll_until_decided().await;
        if let Err(error) = &result
            && std::error::Error::source(error).is_some()
        {
            log::warn!(
                "Pairing with {} failed: {error:?}",
                http::authority(&self.address)
            );
        }
        result
    }

    async fn poll_until_decided(&self) -> Result<Credentials> {
        let url = pair_url(&self.address, &self.request_id, None)?;
        let mut failed_polls = 0;
        loop {
            if since(self.clock.instant(), self.deadline) > EXPIRY_GRACE {
                return Err(Error::of(FailureKind::PairingExpired));
            }

            self.clock.sleep(self.poll_interval).await;
            let response = match self
                .http
                .get(url.clone())
                .header(PAIR_TOKEN_HEADER, &self.poll_token)
                .timeout(self.request_timeout)
                .send()
                .await
            {
                Ok(response) => {
                    failed_polls = 0;
                    response
                }
                Err(cause) => {
                    let error = Error::from_cause(cause);
                    // A blip on the network is not the end of the request: it is still on the
                    // server, and the next poll finds it. A server that stays away is.
                    failed_polls += 1;
                    if failed_polls < MAX_FAILED_POLLS
                        && matches!(
                            error.kind(),
                            FailureKind::Unreachable | FailureKind::ConnectionLost
                        )
                    {
                        log::info!(
                            "A poll of the pairing request on {} failed, trying again: {error:?}",
                            http::authority(&self.address)
                        );
                        continue;
                    }
                    return Err(error);
                }
            };
            match response.status() {
                // Others from this address are pairing too; the next poll is soon enough.
                StatusCode::TOO_MANY_REQUESTS => continue,
                StatusCode::NOT_FOUND => {
                    self.finish();
                    return Err(Error::of(FailureKind::PairingExpired));
                }
                _ => {}
            }
            let poll: PairPoll = response.read_json()?;
            match poll.state {
                PairState::Waiting => {}
                PairState::Approved => match (poll.client_id, poll.client_secret) {
                    (Some(id), Some(secret)) if !id.trim().is_empty() && !secret.is_empty() => {
                        self.finish();
                        log::info!("Paired with {}", self.server_name);
                        return Ok(Credentials::new(id, secret));
                    }
                    _ => return Err(bad_answer("The poll approved without credentials.")),
                },
                PairState::Denied => {
                    self.finish();
                    return Err(Error::of(FailureKind::PairingDenied));
                }
                PairState::Expired => {
                    self.finish();
                    return Err(Error::of(FailureKind::PairingExpired));
                }
                other => {
                    return Err(bad_answer(format!(
                        "The poll answered the state '{}'.",
                        other.as_str()
                    )));
                }
            }
        }
    }

    /// Withdraws the request, when it is still waiting, so it does not sit on the server's list
    /// until it expires. Never fails.
    pub async fn withdraw(&self) {
        withdraw(
            &self.http,
            &self.address,
            &self.request_id,
            &self.poll_token,
            &self.state,
            &self.server_name,
        )
        .await;
    }

    /// The request is over on the server; there is nothing to withdraw.
    fn finish(&self) {
        let _ = self
            .state
            .compare_exchange(WAITING, FINISHED, Ordering::SeqCst, Ordering::SeqCst);
    }
}

impl Drop for PairingClient {
    fn drop(&mut self) {
        // The poll token is the proof of who may withdraw: it is wiped on every way out, and the copy
        // a withdrawing task holds when that is done.
        if self.state.load(Ordering::SeqCst) == WAITING
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            let (http, address, id, token, state, name) = (
                self.http.clone(),
                self.address.clone(),
                self.request_id.clone(),
                self.poll_token.clone(),
                self.state.clone(),
                self.server_name.clone(),
            );
            runtime.spawn(async move {
                let mut token = token;
                withdraw(&http, &address, &id, &token, &state, &name).await;
                token.zeroize();
            });
        }
        self.poll_token.zeroize();
    }
}

async fn withdraw(
    http: &HttpClient,
    address: &Url,
    request_id: &str,
    poll_token: &str,
    state: &AtomicU8,
    server_name: &str,
) {
    if state
        .compare_exchange(WAITING, FINISHED, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }
    let Ok(url) = pair_url(address, request_id, None) else {
        return;
    };
    match http
        .delete(url)
        .header(PAIR_TOKEN_HEADER, poll_token)
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(withdrawn) => log::debug!(
            "Withdrew the pairing request on {server_name}: {}",
            withdrawn.status()
        ),
        // The server expires it on its own.
        Err(error) => {
            log::warn!("Could not withdraw the pairing request on {server_name}: {error}")
        }
    }
}

/// A request ID or poll token that can go in a path and a header as it is: 1 to 128 printable ASCII
/// characters.
fn is_id(text: &str) -> bool {
    (1..=MAX_ID_LENGTH).contains(&text.len()) && text.bytes().all(|b| b > b' ' && b < 0x7f)
}

/// `/skakel/v3/pair/{id}` and what follows it, with the id escaped as one path segment.
fn pair_url(server: &Url, id: &str, tail: Option<&str>) -> Result<Url, Error> {
    let mut url = server.clone();
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|()| bad_answer("The server's address cannot take a path."))?;
        segments
            .clear()
            .extend(PAIR_PATH.trim_matches('/').split('/'));
        segments.push(id);
        if let Some(tail) = tail {
            segments.push(tail);
        }
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_id_takes_short_printable_ascii_that_is_safe_in_a_path() {
        assert!(is_id("abc-123_XYZ"));
        assert!(is_id(&"a".repeat(128)));
        assert!(!is_id(""));
        assert!(!is_id(&"a".repeat(129)));
        assert!(!is_id("a b"));
        assert!(!is_id("a\r\nb"));
        assert!(!is_id("caf\u{e9}"));
    }

    #[test]
    fn pair_url_escapes_the_id_as_one_segment() {
        let server = Url::parse("https://10.0.0.5:5240/").unwrap();

        assert_eq!(
            pair_url(&server, "a/b?c", None).unwrap().as_str(),
            "https://10.0.0.5:5240/skakel/v3/pair/a%2Fb%3Fc"
        );
        assert_eq!(
            pair_url(&server, "r1", Some("reveal")).unwrap().as_str(),
            "https://10.0.0.5:5240/skakel/v3/pair/r1/reveal"
        );
    }
}
