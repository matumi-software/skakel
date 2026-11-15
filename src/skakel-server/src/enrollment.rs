//! Enrolling a client with a pairing code or a server key. See `docs/enrollment.md`.
//!
//! The code is a short password, so it goes through SPAKE2: a recorded exchange tells an attacker
//! nothing about it, and each wrong confirmation is one online guess, counted here. The key is 256
//! bits, so a client only proves it holds it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use skakel_wire::enrollment::{
    CLIENT_IDENTITY, CodeStarted, ConfirmKeys, End, Enrolled, SERVER_IDENTITY, WRONG_CONFIRMATIONS,
    code_transcript, new_code,
};
use skakel_wire::pairing::clean_client_name;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use time::OffsetDateTime;
use tokio::time::Instant;

use crate::error::ServerError;
use crate::state::ServerState;
use crate::util;

/// The shortest time a pairing code can be open.
const MIN_TTL: Duration = Duration::from_secs(30);

/// The longest time a pairing code can be open.
const MAX_TTL: Duration = Duration::from_secs(5 * 60);

/// How long a pairing code stays open when the app does not say.
pub const DEFAULT_TTL: Duration = Duration::from_secs(60);

/// How long an exchange waits for its client's confirmation.
const SESSION_TTL: Duration = Duration::from_secs(30);

/// The most exchanges waiting for a confirmation at once, whatever the callers.
const MAX_SESSIONS: usize = 16;

/// The most bytes of a password-exchange message a server reads. SPAKE2's own is 33.
const MAX_PAKE_BYTES: usize = 64;

/// A pairing code the server is showing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OpenedCode {
    /// The eight digits.
    pub code: String,
    /// When it stops working.
    pub expires_at: OffsetDateTime,
}

/// Why an enrolment call was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// There is no pairing code open, or no server key made.
    Closed,
    /// The server has as many exchanges waiting as it takes.
    Busy,
    /// The call was not made right: the text says how.
    Invalid(&'static str),
    /// No such exchange, or the confirmation was wrong or came too late. One answer for all of
    /// them, so a wrong code is no different from an old one.
    NotFound,
    /// The server could not do it: a failure to save or to get random bytes.
    Failed,
}

struct OpenCode {
    code: String,
    until: Instant,
    expires_at: OffsetDateTime,
    wrong: u32,
}

struct Exchange {
    keys: ConfirmKeys,
    transcript: Vec<u8>,
    name: String,
    until: Instant,
}

#[derive(Default)]
struct Inner {
    code: Option<OpenCode>,
    exchanges: HashMap<String, Exchange>,
}

impl Inner {
    fn sweep(&mut self, now: Instant) {
        if self.code.as_ref().is_some_and(|open| open.until <= now) {
            self.code = None;
        }
        self.exchanges.retain(|_, exchange| exchange.until > now);
    }
}

/// The server's enrolment: the pairing code it shows, the exchanges under way and the server key.
#[derive(Clone)]
pub struct Enrollment {
    state: Arc<ServerState>,
    inner: Arc<Mutex<Inner>>,
}

impl Enrollment {
    pub(crate) fn new(state: Arc<ServerState>) -> Self {
        Self {
            state,
            inner: Arc::new(Mutex::new(Inner::default())),
        }
    }

    /// Shows a new pairing code, replacing any open one, for `ttl` (held to between 30 seconds and
    /// five minutes). It works once: a client that enrols with it, three wrong confirmations or
    /// the end of the time spend it.
    pub fn open_code(&self, ttl: Duration) -> Result<OpenedCode, ServerError> {
        let ttl = ttl.clamp(MIN_TTL, MAX_TTL);
        let code = new_code()?;
        let expires_at = OffsetDateTime::now_utc() + ttl;
        let mut inner = self.inner.lock().expect("enrolment lock");
        // A new code is a new password: the exchanges made with the old one cannot confirm.
        inner.exchanges.clear();
        inner.code = Some(OpenCode {
            code: code.clone(),
            until: Instant::now() + ttl,
            expires_at,
            wrong: 0,
        });
        Ok(OpenedCode { code, expires_at })
    }

    /// Closes the pairing code now.
    pub fn close_code(&self) {
        let mut inner = self.inner.lock().expect("enrolment lock");
        inner.code = None;
        inner.exchanges.clear();
    }

    /// The pairing code that is showing, if it still is.
    pub fn code(&self) -> Option<OpenedCode> {
        let mut inner = self.inner.lock().expect("enrolment lock");
        inner.sweep(Instant::now());
        inner.code.as_ref().map(|open| OpenedCode {
            code: open.code.clone(),
            expires_at: open.expires_at,
        })
    }

    /// The server key as text, made the first time it is asked for. A client with it can enrol at
    /// any time. Its text is made from the secret and the certificate in use, so a certificate
    /// switch changes it.
    pub async fn key(&self) -> Result<String, ServerError> {
        Ok(self.state.make_enrollment_key(false).await?.encode())
    }

    /// Makes a new server key and spends the old one. Clients already enrolled are not affected.
    pub async fn rotate_key(&self) -> Result<String, ServerError> {
        Ok(self.state.make_enrollment_key(true).await?.encode())
    }

    /// Whether a pairing code is open or a server key exists: what `info` lists.
    pub(crate) fn methods(&self) -> Vec<String> {
        let mut methods = vec![skakel_wire::enrollment::METHOD_CODE.to_owned()];
        if self.state.enrollment_key().is_some() {
            methods.push(skakel_wire::enrollment::METHOD_KEY.to_owned());
        }
        methods
    }

    /// Starts an exchange: the client's name and message in, the server's message out.
    pub(crate) fn start(
        &self,
        client_name: &str,
        client_pake: &str,
    ) -> Result<CodeStarted, Refusal> {
        let client_message =
            decode(client_pake).ok_or(Refusal::Invalid("The pake message is not base64url."))?;
        let mut inner = self.inner.lock().expect("enrolment lock");
        inner.sweep(Instant::now());
        let Some(open) = inner.code.as_ref() else {
            return Err(Refusal::Closed);
        };
        if inner.exchanges.len() >= MAX_SESSIONS {
            return Err(Refusal::Busy);
        }
        let (exchange, server_message) = Spake2::<Ed25519Group>::start_b(
            &Password::new(open.code.as_bytes()),
            &Identity::new(CLIENT_IDENTITY),
            &Identity::new(SERVER_IDENTITY),
        );
        let key = exchange
            .finish(&client_message)
            .map_err(|_| Refusal::Invalid("The pake message is not one the exchange can use."))?;
        let transcript = code_transcript(
            &self.state.fingerprint_bytes(),
            client_name,
            &client_message,
            &server_message,
        );
        let id = util::new_id("enroll").map_err(|_| Refusal::Failed)?;
        let until = Instant::now() + SESSION_TTL;
        inner.exchanges.insert(
            id.clone(),
            Exchange {
                keys: ConfirmKeys::derive(&key),
                transcript,
                name: client_name.to_owned(),
                until,
            },
        );
        Ok(CodeStarted {
            enroll_id: id,
            pake: URL_SAFE_NO_PAD.encode(server_message),
            expires_at: OffsetDateTime::now_utc()
                .saturating_add(
                    time::Duration::try_from(SESSION_TTL).unwrap_or(time::Duration::ZERO),
                )
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        })
    }

    /// Checks a confirmation. A match spends the code and registers the client; a miss counts as
    /// one wrong guess, and the third spends the code. Either way the exchange is used up.
    pub(crate) async fn confirm(&self, id: &str, mac: &str) -> Result<Enrolled, Refusal> {
        let mac = decode(mac).ok_or(Refusal::Invalid("The mac is not base64url."))?;
        let (name, server_mac) = {
            let mut inner = self.inner.lock().expect("enrolment lock");
            inner.sweep(Instant::now());
            let exchange = inner.exchanges.remove(id).ok_or(Refusal::NotFound)?;
            let Some(open) = inner.code.as_mut() else {
                return Err(Refusal::NotFound);
            };
            if !exchange
                .keys
                .verify(End::Client, &exchange.transcript, &mac)
            {
                open.wrong += 1;
                if open.wrong >= WRONG_CONFIRMATIONS {
                    inner.code = None;
                    inner.exchanges.clear();
                }
                return Err(Refusal::NotFound);
            }
            // Spent before the client is registered, so a second confirmation cannot also get in.
            inner.code = None;
            inner.exchanges.clear();
            (
                exchange.name,
                exchange.keys.mac(End::Server, &exchange.transcript),
            )
        };
        let registered = self
            .state
            .register_client_with(&clean_client_name(&name), Some("code"))
            .await
            .map_err(|_| Refusal::Failed)?;
        Ok(Enrolled {
            mac: URL_SAFE_NO_PAD.encode(server_mac),
            client_id: registered.client_id,
            client_secret: registered.client_secret,
        })
    }

    /// Enrols with the server key: the client's name, nonce and proof in, the server's proof and the
    /// credentials out. A wrong proof is [`Refusal::NotFound`], whatever was wrong with it.
    pub(crate) async fn enrol_with_key(
        &self,
        client_name: &str,
        nonce: &str,
        mac: &str,
    ) -> Result<Enrolled, Refusal> {
        let Some(key) = self.state.enrollment_key() else {
            return Err(Refusal::Closed);
        };
        // The nonce is 32 bytes as base64url, 43 characters; a longer one is more than needed.
        if !(43..=128).contains(&nonce.len())
            || !nonce
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(Refusal::Invalid("The nonce is not 32 bytes as base64url."));
        }
        let proof = decode(mac).ok_or(Refusal::Invalid("The mac is not base64url."))?;
        let fingerprint = self.state.fingerprint_bytes();
        if !key.verify(End::Client, &fingerprint, client_name, nonce, &proof) {
            return Err(Refusal::NotFound);
        }
        let server_mac = key.mac(End::Server, &fingerprint, client_name, nonce);
        let registered = self
            .state
            .register_client_with(&clean_client_name(client_name), Some("key"))
            .await
            .map_err(|_| Refusal::Failed)?;
        Ok(Enrolled {
            mac: URL_SAFE_NO_PAD.encode(server_mac),
            client_id: registered.client_id,
            client_secret: registered.client_secret,
        })
    }
}

fn decode(text: &str) -> Option<Vec<u8>> {
    if text.len() > MAX_PAKE_BYTES * 2 {
        return None;
    }
    URL_SAFE_NO_PAD
        .decode(text)
        .ok()
        .filter(|bytes| bytes.len() <= MAX_PAKE_BYTES)
}
