//! Enrolling with a server by a pairing code or a server key, so the client gets its credentials
//! with nothing to approve on the server. See `docs/enrollment.md`.
//!
//! The first call, `info`, is made to a server whose certificate the client has not yet been told
//! to trust: it only reads the fingerprint of whatever certificate answers. Every call after that
//! is pinned to that fingerprint, and the exchange proves the server was holding the code or the
//! key while presenting that same certificate, so a stranger in the middle gets nothing.

use std::fmt;
use std::time::Duration;

use ::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use skakel_wire::enrollment::{
    CLIENT_IDENTITY, CodeConfirm, CodeStart, CodeStarted, ConfirmKeys, ENROLL_CODE_PATH,
    ENROLL_KEY_PATH, End, Enrolled, KeyEnroll, KeyError, METHOD_CODE, METHOD_KEY, REASON_CLOSED,
    SERVER_IDENTITY, ServerKey, code_transcript, normalise_code,
};
use skakel_wire::fingerprints;
use skakel_wire::pairing::{RandomError, new_nonce};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use url::Url;

use crate::failure::{Error, FailureKind, bad_answer};
use crate::http::{base_address, presented};
use crate::info::{read_info_with, require_version};
use crate::options::ClientOptions;
use crate::pins::{Credentials, Pins};
use crate::request::HttpClient;

/// The longest a client name is, in Unicode scalar values as the server counts them.
const MAX_CLIENT_NAME_LENGTH: usize = 80;

/// Why a client could not be enrolled.
#[derive(Debug)]
#[non_exhaustive]
pub enum EnrollError {
    /// The client's name is empty once trimmed, or longer than 80 characters.
    InvalidClientName,
    /// What was typed is not a pairing code: eight digits.
    InvalidCode,
    /// What was typed is not a server key.
    InvalidKey(KeyError),
    /// The operating system had no random numbers.
    NoRandomness(RandomError),
    /// The server does not enrol clients this way: it is an older Skakel, or has no server key.
    NotSupported,
    /// The server key is for another server: the certificate at this address is not the one the key
    /// was made for.
    KeyForAnotherServer,
    /// The server is showing no pairing code, or has no server key to take.
    Closed,
    /// The code or the key was wrong, or the code ran out or was spent.
    Refused,
    /// The server could not be reached, speaks no common version, or did not answer as a Skakel
    /// server does, which includes failing to prove it knew the code or key.
    Failed(Error),
}

impl fmt::Display for EnrollError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidClientName => f.write_str("Give the client a name of 1 to 80 characters."),
            Self::InvalidCode => f.write_str("A pairing code is eight digits."),
            Self::InvalidKey(error) => error.fmt(f),
            Self::NoRandomness(error) => error.fmt(f),
            Self::NotSupported => f.write_str(
                "This server cannot be added with a code or a key. Update it, or pair with it from the server's own screen.",
            ),
            Self::KeyForAnotherServer => f.write_str("That server key is for another server. Check the address, or copy the key again."),
            Self::Closed => f.write_str("The server is not showing a pairing code. Show one on the server and try again."),
            Self::Refused => f.write_str("The code or the key was not accepted. Check it, or show a new code on the server."),
            Self::Failed(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for EnrollError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Failed(error) => Some(error),
            Self::NoRandomness(error) => Some(error),
            Self::InvalidKey(error) => Some(error),
            _ => None,
        }
    }
}

impl From<Error> for EnrollError {
    fn from(error: Error) -> Self {
        Self::Failed(error)
    }
}

/// What a successful enrolment gives the app to keep: the credentials for the server, the
/// certificate to pin, and the name the server goes by.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Enrollment {
    /// The client ID and secret on that server.
    pub credentials: Credentials,
    /// The certificate to trust from now on.
    pub pins: Pins,
    /// The name the server gives itself.
    pub server_name: String,
}

/// Enrols with a pairing code the server is showing.
///
/// - `address` is the server's HTTPS address, typed or from discovery.
/// - `code` is the eight digits, as typed (spaces and dashes between them are fine).
/// - `client_name` is what the server's people see this client as: 1 to 80 characters.
pub async fn enroll_with_code(
    address: &Url,
    code: &str,
    client_name: &str,
    options: &ClientOptions,
) -> Result<Enrollment, EnrollError> {
    let name = client_name.trim();
    check_name(name)?;
    let code = normalise_code(code).ok_or(EnrollError::InvalidCode)?;
    let server = base_address(address)?;
    let timeout = options.request_timeout;
    let (client, fingerprint, server_name) = meet(&server, METHOD_CODE, timeout).await?;

    let (exchange, client_message) = Spake2::<Ed25519Group>::start_a(
        &Password::new(code.as_bytes()),
        &Identity::new(CLIENT_IDENTITY),
        &Identity::new(SERVER_IDENTITY),
    );
    let started = client
        .post(server.join(ENROLL_CODE_PATH).map_err(Error::from_cause)?)
        .timeout(timeout)
        .json(&CodeStart {
            client_name: name.to_owned(),
            pake: URL_SAFE_NO_PAD.encode(&client_message),
        })
        .send()
        .await;
    let started = match started {
        Ok(response) => response,
        Err(error) => return Err(error.into()),
    };
    if started.status() == StatusCode::FORBIDDEN && is_closed(&started) {
        return Err(EnrollError::Closed);
    }
    let started: CodeStarted = started.read_json()?;
    let server_message = decode(&started.pake)
        .ok_or_else(|| bad_answer("The enrolment answer's pake message is not base64url."))?;
    let key = exchange
        .finish(&server_message)
        .map_err(|_| bad_answer("The enrolment answer's pake message cannot be used."))?;
    let keys = ConfirmKeys::derive(&key);
    // The certificate this client saw is in the transcript: a server behind another certificate
    // cannot make a confirmation that matches, and cannot learn the code from this one.
    let transcript = code_transcript(&fingerprint, name, &client_message, &server_message);
    let confirm_url = server
        .join(&format!("{ENROLL_CODE_PATH}/{}/confirm", started.enroll_id))
        .map_err(Error::from_cause)?;
    let confirmed = client
        .post(confirm_url)
        .timeout(timeout)
        .json(&CodeConfirm {
            mac: URL_SAFE_NO_PAD.encode(keys.mac(End::Client, &transcript)),
        })
        .send()
        .await?;
    if confirmed.status() == StatusCode::NOT_FOUND {
        return Err(EnrollError::Refused);
    }
    let enrolled: Enrolled = confirmed
        .ensure_success()
        .and_then(|()| confirmed.read_json())?;
    let proof = decode(&enrolled.mac)
        .ok_or_else(|| bad_answer("The enrolment answer's mac is not base64url."))?;
    if !keys.verify(End::Server, &transcript, &proof) {
        return Err(not_proved());
    }
    finish(enrolled, &fingerprint, server_name)
}

/// Enrols with a server key copied from the server.
///
/// - `address` is the server's HTTPS address, typed or from discovery.
/// - `key` is the key as text, `kp1_` and 77 characters.
/// - `client_name` is what the server's people see this client as: 1 to 80 characters.
pub async fn enroll_with_key(
    address: &Url,
    key: &str,
    client_name: &str,
    options: &ClientOptions,
) -> Result<Enrollment, EnrollError> {
    let name = client_name.trim();
    check_name(name)?;
    let key = ServerKey::parse(key).map_err(EnrollError::InvalidKey)?;
    let server = base_address(address)?;
    let timeout = options.request_timeout;
    let (client, fingerprint, server_name) = meet(&server, METHOD_KEY, timeout).await?;
    // The key says which certificate it is for. Nothing secret has been sent yet.
    if !key.is_for(&fingerprint) {
        return Err(EnrollError::KeyForAnotherServer);
    }
    let nonce = new_nonce().map_err(EnrollError::NoRandomness)?;
    let response = client
        .post(server.join(ENROLL_KEY_PATH).map_err(Error::from_cause)?)
        .timeout(timeout)
        .json(&KeyEnroll {
            client_name: name.to_owned(),
            nonce: nonce.clone(),
            mac: URL_SAFE_NO_PAD.encode(key.mac(End::Client, &fingerprint, name, &nonce)),
        })
        .send()
        .await?;
    if response.status() == StatusCode::FORBIDDEN && is_closed(&response) {
        return Err(EnrollError::Closed);
    }
    if response.status() == StatusCode::NOT_FOUND {
        return Err(EnrollError::Refused);
    }
    let enrolled: Enrolled = response
        .ensure_success()
        .and_then(|()| response.read_json())?;
    let proof = decode(&enrolled.mac)
        .ok_or_else(|| bad_answer("The enrolment answer's mac is not base64url."))?;
    if !key.verify(End::Server, &fingerprint, name, &nonce, &proof) {
        return Err(not_proved());
    }
    finish(enrolled, &fingerprint, server_name)
}

fn check_name(name: &str) -> Result<(), EnrollError> {
    if name.is_empty() || name.chars().count() > MAX_CLIENT_NAME_LENGTH {
        return Err(EnrollError::InvalidClientName);
    }
    Ok(())
}

/// Reads `info` from a server whose certificate is not yet trusted, only to learn the fingerprint
/// it presents, and gives a client pinned to that fingerprint for everything after. Nothing secret
/// is sent here.
async fn meet(
    server: &Url,
    method: &str,
    timeout: Duration,
) -> Result<(HttpClient, [u8; fingerprints::BYTES], String), EnrollError> {
    let seen = presented();
    let probe = HttpClient::probing(seen.clone());
    let info = read_info_with(&probe, server, timeout).await?;
    require_version(&info.versions)?;
    if !info.enroll.iter().any(|m| m == method) {
        return Err(EnrollError::NotSupported);
    }
    let fingerprint = crate::http::last_presented(&seen)
        .and_then(|text| fingerprints::to_bytes(&text))
        .ok_or_else(|| Error::of(FailureKind::CertificateMismatch))?;
    let pins = Pins::new(
        &fingerprints::from_bytes(&fingerprint)
            .ok_or_else(|| Error::of(FailureKind::CertificateMismatch))?,
    )
    .map_err(|e| Error::caused(FailureKind::CertificateMismatch, e))?;
    Ok((HttpClient::pinned(pins), fingerprint, info.name))
}

fn finish(
    enrolled: Enrolled,
    fingerprint: &[u8; fingerprints::BYTES],
    server_name: String,
) -> Result<Enrollment, EnrollError> {
    let text = fingerprints::from_bytes(fingerprint)
        .ok_or_else(|| Error::of(FailureKind::CertificateMismatch))?;
    let pins = Pins::new(&text).map_err(|e| Error::caused(FailureKind::CertificateMismatch, e))?;
    Ok(Enrollment {
        credentials: Credentials::new(enrolled.client_id, enrolled.client_secret),
        pins,
        server_name,
    })
}

/// The server answered, but did not prove it held the code or the key, so what it said is not
/// trusted and the credentials it sent are dropped.
fn not_proved() -> EnrollError {
    EnrollError::Failed(bad_answer(
        "The server did not prove it had the code or the key.",
    ))
}

fn is_closed(response: &crate::request::Response) -> bool {
    response
        .json::<serde_json::Value>()
        .ok()
        .and_then(|body| {
            body.get("reason")
                .and_then(|r| r.as_str().map(str::to_owned))
        })
        .is_some_and(|reason| reason == REASON_CLOSED)
}

fn decode(text: &str) -> Option<Vec<u8>> {
    (text.len() <= 128)
        .then(|| URL_SAFE_NO_PAD.decode(text).ok())
        .flatten()
}
