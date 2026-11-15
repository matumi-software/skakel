//! The server key: 32 secret bytes and the first 16 bytes of the server certificate's fingerprint,
//! written as `kp1_` and Crockford base32.

use subtle::ConstantTimeEq;

use super::{End, MAC_BYTES, key_transcript, mac, verify};
use crate::fingerprints::BYTES as FINGERPRINT_BYTES;
use crate::pairing::{RandomError, random_bytes};

/// What every server key starts with.
pub const KEY_PREFIX: &str = "kp1_";

const SECRET_BYTES: usize = 32;
const TAG_BYTES: usize = 16;
/// 48 bytes are 384 bits, which take 77 characters of 5 bits.
const CHARACTERS: usize = (SECRET_BYTES + TAG_BYTES) * 8 / 5 + 1;
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Why a text is not a server key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// It does not start with `kp1_`.
    Prefix,
    /// It is the wrong length, or has a character outside the alphabet.
    Malformed,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            KeyError::Prefix => "That is not a server key: it should start with kp1_.",
            KeyError::Malformed => {
                "That server key is not written right. Copy it again from the server."
            }
        })
    }
}

impl std::error::Error for KeyError {}

/// A server key: the secret and the certificate tag it is for.
#[derive(Clone)]
pub struct ServerKey {
    secret: [u8; SECRET_BYTES],
    tag: [u8; TAG_BYTES],
}

impl ServerKey {
    /// A new key for the certificate with this fingerprint.
    pub fn generate(fingerprint: &[u8; FINGERPRINT_BYTES]) -> Result<Self, RandomError> {
        let secret = random_bytes::<SECRET_BYTES>()?;
        let mut tag = [0u8; TAG_BYTES];
        tag.copy_from_slice(&fingerprint[..TAG_BYTES]);
        Ok(Self { secret, tag })
    }

    /// The key made from a stored secret and the certificate in use.
    pub fn from_secret(secret: [u8; 32], fingerprint: &[u8; FINGERPRINT_BYTES]) -> Self {
        let mut tag = [0u8; TAG_BYTES];
        tag.copy_from_slice(&fingerprint[..TAG_BYTES]);
        Self { secret, tag }
    }

    /// The secret half, for a server that keeps it between runs. The text of the key is made again
    /// from it and the certificate in use with [`from_secret`](Self::from_secret).
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret
    }

    /// The key as text: `kp1_` and 77 base32 characters.
    pub fn encode(&self) -> String {
        let mut bytes = [0u8; SECRET_BYTES + TAG_BYTES];
        bytes[..SECRET_BYTES].copy_from_slice(&self.secret);
        bytes[SECRET_BYTES..].copy_from_slice(&self.tag);
        let mut out = String::from(KEY_PREFIX);
        let mut buffer = 0u32;
        let mut bits = 0u32;
        for byte in bytes {
            buffer = (buffer << 8) | u32::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
            }
            buffer &= (1 << bits) - 1;
        }
        if bits > 0 {
            out.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
        }
        out
    }

    /// Reads a key as typed or pasted: case and surrounding spaces do not matter, and the Crockford
    /// look-alikes (`O` for 0, `I` and `L` for 1) are taken as what they look like.
    pub fn parse(text: &str) -> Result<Self, KeyError> {
        let text = text.trim();
        let head = text.get(..KEY_PREFIX.len()).ok_or(KeyError::Prefix)?;
        if !head.eq_ignore_ascii_case(KEY_PREFIX) {
            return Err(KeyError::Prefix);
        }
        let body = &text[KEY_PREFIX.len()..];
        if body.chars().count() != CHARACTERS {
            return Err(KeyError::Malformed);
        }
        let mut bytes = Vec::with_capacity(SECRET_BYTES + TAG_BYTES);
        let mut buffer = 0u32;
        let mut bits = 0u32;
        for c in body.chars() {
            let c = match c.to_ascii_uppercase() {
                'O' => '0',
                'I' | 'L' => '1',
                other => other,
            };
            let value = ALPHABET
                .iter()
                .position(|&a| char::from(a) == c)
                .ok_or(KeyError::Malformed)?;
            buffer = (buffer << 5) | value as u32;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                bytes.push(((buffer >> bits) & 0xFF) as u8);
                buffer &= (1 << bits) - 1;
            }
        }
        // 48 bytes are 384 bits and 77 characters carry 385, so one spare bit that must be zero.
        if bytes.len() != SECRET_BYTES + TAG_BYTES || buffer != 0 {
            return Err(KeyError::Malformed);
        }
        let mut secret = [0u8; SECRET_BYTES];
        let mut tag = [0u8; TAG_BYTES];
        secret.copy_from_slice(&bytes[..SECRET_BYTES]);
        tag.copy_from_slice(&bytes[SECRET_BYTES..]);
        Ok(Self { secret, tag })
    }

    /// True when the certificate with this fingerprint is the one the key was made for.
    pub fn is_for(&self, fingerprint: &[u8; FINGERPRINT_BYTES]) -> bool {
        bool::from(self.tag.ct_eq(&fingerprint[..TAG_BYTES]))
    }

    /// The MAC `end` sends for this client name and nonce, with `fingerprint` the certificate that
    /// end saw (a server puts in its own).
    pub fn mac(
        &self,
        end: End,
        fingerprint: &[u8; FINGERPRINT_BYTES],
        client_name: &str,
        nonce: &str,
    ) -> [u8; MAC_BYTES] {
        mac(
            &self.secret,
            end,
            &key_transcript(fingerprint, client_name, nonce),
        )
    }

    /// True when `received` is the MAC `end` would send, compared in constant time.
    pub fn verify(
        &self,
        end: End,
        fingerprint: &[u8; FINGERPRINT_BYTES],
        client_name: &str,
        nonce: &str,
        received: &[u8],
    ) -> bool {
        verify(
            &self.secret,
            end,
            &key_transcript(fingerprint, client_name, nonce),
            received,
        )
    }

    /// True when both keys hold the same secret, compared in constant time.
    pub fn same_secret(&self, other: &Self) -> bool {
        bool::from(self.secret.ct_eq(&other.secret))
    }
}

impl std::fmt::Debug for ServerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ServerKey(..)")
    }
}
