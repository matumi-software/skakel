//! What can go wrong starting or running the server.

use std::fmt;
use std::io;

use crate::crypto::CryptoError;

/// An error from the server's own work.
#[derive(Debug)]
pub enum ServerError {
    /// The store could not load or save the state.
    Store(io::Error),
    /// A key or certificate could not be made.
    Crypto(CryptoError),
    /// The saved state holds something that cannot be used.
    State(String),
    /// An argument the server cannot take.
    Invalid(String),
    /// The options are wrong; each entry says which and why.
    Options(Vec<String>),
    /// The TCP port could not be bound.
    Bind(io::Error),
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(f, "the state store failed: {error}"),
            Self::Crypto(error) => write!(f, "{error}"),
            Self::State(text) | Self::Invalid(text) => f.write_str(text),
            Self::Options(problems) => write!(f, "invalid options: {}", problems.join(" ")),
            Self::Bind(error) => write!(f, "could not listen: {error}"),
        }
    }
}

impl std::error::Error for ServerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(error) | Self::Bind(error) => Some(error),
            Self::Crypto(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CryptoError> for ServerError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}
