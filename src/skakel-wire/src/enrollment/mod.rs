//! Enrolling a client with a pairing code or a server key: the paths, the key's text form, the
//! transcripts both ends hash and the confirmation MACs. The password exchange for the code runs in
//! `skakel-client` and `skakel-server`, which take its session key to [`ConfirmKeys::derive`]. See
//! `docs/enrollment.md`.

mod bodies;
mod key;

pub use bodies::{CodeConfirm, CodeStart, CodeStarted, Enrolled, KeyEnroll};
pub use key::{KEY_PREFIX, KeyError, ServerKey};

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::fingerprints::BYTES as FINGERPRINT_BYTES;
use crate::pairing::{DIGITS, RandomError, random_bytes};

/// Starts an enrolment with a pairing code: `POST`. Confirming is
/// `POST {ENROLL_CODE_PATH}/{enrollId}/confirm`.
pub const ENROLL_CODE_PATH: &str = "/skakel/v3/enroll/code";

/// Enrols with a server key: `POST`.
pub const ENROLL_KEY_PATH: &str = "/skakel/v3/enroll/key";

/// What a server lists in `info` under `enroll` when it takes a pairing code.
pub const METHOD_CODE: &str = "code";

/// What a server lists in `info` under `enroll` when it takes a server key.
pub const METHOD_KEY: &str = "key";

/// The reason a server gives when it has no pairing code open.
pub const REASON_CLOSED: &str = "enrolment-closed";

/// How many wrong confirmations spend a pairing code.
pub const WRONG_CONFIRMATIONS: u32 = 3;

/// The bytes of a confirmation MAC.
pub const MAC_BYTES: usize = 32;

const CODE_TAG: &str = "skakel-enroll-code-v1";
const KEY_TAG: &str = "skakel-enroll-key-v1";

/// Which end made a MAC. The two ends use different first bytes so one cannot be replayed as the
/// other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    /// The client's confirmation.
    Client,
    /// The server's confirmation.
    Server,
}

impl End {
    fn label(self) -> &'static [u8] {
        match self {
            End::Client => b"c",
            End::Server => b"s",
        }
    }
}

/// Appends `part` with its length as 4 bytes, big-endian, so where one part ends is never in doubt.
fn lp(out: &mut Vec<u8>, part: &[u8]) {
    out.extend_from_slice(&u32::try_from(part.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(part);
}

/// A new pairing code: eight uniform random digits.
pub fn new_code() -> Result<String, RandomError> {
    // 4,000,000,000 is a multiple of 100,000,000, so taking the remainder is uniform.
    loop {
        let n = u32::from_be_bytes(random_bytes::<4>()?);
        if n < 4_000_000_000 {
            return Ok(format!("{:0width$}", n % 100_000_000, width = DIGITS));
        }
    }
}

/// The eight digits of a pairing code as typed (spaces and dashes between them are allowed), or
/// `None` when the text is not a code.
pub fn normalise_code(text: &str) -> Option<String> {
    let digits: String = text.chars().filter(|c| !matches!(c, ' ' | '-')).collect();
    (digits.len() == DIGITS && digits.bytes().all(|b| b.is_ascii_digit())).then_some(digits)
}

/// The transcript both ends hash for a code enrolment. `fingerprint` is the 32 bytes of the
/// certificate the **client saw** (a server puts in its own), then the name the client sent and the
/// two password-exchange messages.
pub fn code_transcript(
    fingerprint: &[u8; FINGERPRINT_BYTES],
    client_name: &str,
    client_message: &[u8],
    server_message: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    lp(&mut out, CODE_TAG.as_bytes());
    lp(&mut out, fingerprint);
    lp(&mut out, client_name.as_bytes());
    lp(&mut out, client_message);
    lp(&mut out, server_message);
    out
}

/// The transcript for a key enrolment, `nonce` being what the client sent.
pub fn key_transcript(fingerprint: &[u8; FINGERPRINT_BYTES], client_name: &str, nonce: &str) -> Vec<u8> {
    let mut out = Vec::new();
    lp(&mut out, KEY_TAG.as_bytes());
    lp(&mut out, fingerprint);
    lp(&mut out, client_name.as_bytes());
    lp(&mut out, nonce.as_bytes());
    out
}

/// The two confirmation keys of a code enrolment, from the password exchange's session key.
#[derive(Clone)]
pub struct ConfirmKeys {
    client: [u8; 32],
    server: [u8; 32],
}

impl ConfirmKeys {
    /// Expands the session key with HKDF-SHA256 into one key per end.
    pub fn derive(session_key: &[u8]) -> Self {
        let hkdf = Hkdf::<Sha256>::new(Some(CODE_TAG.as_bytes()), session_key);
        let mut client = [0u8; 32];
        let mut server = [0u8; 32];
        // 32 bytes is far below HKDF-SHA256's limit, so these cannot fail.
        let _ = hkdf.expand(b"client confirm", &mut client);
        let _ = hkdf.expand(b"server confirm", &mut server);
        Self { client, server }
    }

    fn key(&self, end: End) -> &[u8; 32] {
        match end {
            End::Client => &self.client,
            End::Server => &self.server,
        }
    }

    /// The MAC `end` sends for `transcript`.
    pub fn mac(&self, end: End, transcript: &[u8]) -> [u8; MAC_BYTES] {
        mac(self.key(end), end, transcript)
    }

    /// True when `received` is the MAC `end` would send for `transcript`, compared in constant time.
    pub fn verify(&self, end: End, transcript: &[u8], received: &[u8]) -> bool {
        verify(self.key(end), end, transcript, received)
    }
}

impl std::fmt::Debug for ConfirmKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConfirmKeys(..)")
    }
}

fn hmac_of(key: &[u8], end: End, transcript: &[u8]) -> Hmac<Sha256> {
    // HMAC takes a key of any length, so this cannot fail.
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap_or_else(|_| unreachable!());
    mac.update(end.label());
    mac.update(transcript);
    mac
}

/// HMAC-SHA256 of the end's label and the transcript.
pub(crate) fn mac(key: &[u8], end: End, transcript: &[u8]) -> [u8; MAC_BYTES] {
    hmac_of(key, end, transcript).finalize().into_bytes().into()
}

/// Constant-time check that `received` is the MAC for `end` and `transcript` under `key`.
pub(crate) fn verify(key: &[u8], end: End, transcript: &[u8], received: &[u8]) -> bool {
    hmac_of(key, end, transcript).verify_slice(received).is_ok()
}
