//! What can go wrong starting or running the server.

use std::error::Error;
use std::fmt;
use std::io;

use skakel_wire::discovery::MAX_APP_VERSION_LENGTH;
use skakel_wire::pairing::RandomError;

use crate::crypto::CryptoError;

/// A source an error carries without naming the library it came from.
pub(crate) type Source = Box<dyn Error + Send + Sync>;

/// An error from the server's own work.
#[derive(Debug)]
#[non_exhaustive]
pub enum ServerError {
    /// The store could not load or save the state.
    Store(io::Error),
    /// A key or certificate could not be made.
    Crypto(CryptoError),
    /// The saved state holds something that cannot be used.
    State(StateError),
    /// TLS could not be set up with the server's certificate.
    Tls(Source),
    /// A client's name is empty once control and format characters and the spaces around it are
    /// taken out.
    InvalidName,
    /// A stream end's reason is not upper case letters, digits and `_`, starting with a letter, at
    /// most 63 characters. It carries the reason.
    InvalidReason(String),
    /// The options are wrong; each entry says which and why.
    Options(Vec<OptionProblem>),
    /// The TCP port could not be bound.
    Bind(io::Error),
    /// The operating system had no random bytes to make a secret, an id or a token with.
    Random(RandomError),
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(f, "the state store failed: {error}"),
            Self::Crypto(error) => write!(f, "{error}"),
            Self::State(error) => write!(f, "{error}"),
            Self::Tls(error) => write!(f, "TLS could not be set up: {error}"),
            Self::InvalidName => f.write_str(
                "The name is empty once control and format characters and the spaces around it are taken out.",
            ),
            Self::InvalidReason(reason) => write!(
                f,
                "The reason '{reason}' must be upper case letters, digits and _, start with a letter and be at most 63 characters."
            ),
            Self::Options(problems) => {
                f.write_str("invalid options:")?;
                for problem in problems {
                    write!(f, " {problem}")?;
                }
                Ok(())
            }
            Self::Bind(error) => write!(f, "could not listen: {error}"),
            Self::Random(error) => write!(f, "{error}"),
        }
    }
}

impl Error for ServerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) | Self::Bind(error) => Some(error),
            Self::Crypto(error) => Some(error),
            Self::State(error) => Some(error),
            Self::Tls(error) => Some(error.as_ref()),
            Self::Random(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CryptoError> for ServerError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

/// What is wrong with a saved state the store returned.
#[derive(Debug)]
#[non_exhaustive]
pub enum StateError {
    /// A saved certificate or key is not base64.
    NotBase64(Source),
    /// The saved certificate's private key cannot be used.
    KeyUnusable(Source),
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotBase64(error) => {
                write!(f, "a saved certificate or key is not base64: {error}")
            }
            Self::KeyUnusable(error) => {
                write!(f, "the saved certificate key is unusable: {error}")
            }
        }
    }
}

impl Error for StateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::NotBase64(error) | Self::KeyUnusable(error) => Some(error.as_ref()),
        }
    }
}

/// One thing wrong with the options of a [`SkakelServerBuilder`](crate::SkakelServerBuilder).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OptionProblem {
    /// The app id is not 1 to 32 of `a-z`, `0-9` and `-`.
    AppId,
    /// The app version is empty or too long.
    AppVersion,
    /// The server's name is empty.
    Name,
    /// A rate limit allows no request a minute.
    RateLimits,
    /// The certificate host name is empty.
    CertificateHostName,
    /// The gRPC service is not in a package of the app's own. It carries the service's name.
    ServiceName(String),
    /// The gRPC service was added twice. It carries the service's name.
    ServiceAddedTwice(String),
    /// The stream type is not from `a-z`, `0-9` and `-`. It carries the type.
    StreamType(String),
    /// A mounted server with discovery was not given the port the app's listener bound.
    DiscoveryPort,
}

impl fmt::Display for OptionProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AppId => f.write_str("The app id must be 1 to 32 of a-z, 0-9 and -."),
            Self::AppVersion => write!(
                f,
                "The app version must be 1 to {MAX_APP_VERSION_LENGTH} characters."
            ),
            Self::Name => f.write_str("The name must not be empty."),
            Self::RateLimits => {
                f.write_str("The rate limits must allow at least one request a minute.")
            }
            Self::CertificateHostName => {
                f.write_str("The certificate host name must not be empty.")
            }
            Self::ServiceName(name) => write!(
                f,
                "The gRPC service '{name}' must be in a package of the app's own, not skakel or one under it."
            ),
            Self::ServiceAddedTwice(name) => {
                write!(f, "The gRPC service '{name}' was added twice.")
            }
            Self::StreamType(stream_type) => write!(
                f,
                "The stream type '{stream_type}' must be from a-z, 0-9 and -."
            ),
            Self::DiscoveryPort => f.write_str(
                "Give the address the app's listener is bound to, with the port it bound, for discovery to announce.",
            ),
        }
    }
}

impl From<RandomError> for ServerError {
    fn from(error: RandomError) -> Self {
        Self::Random(error)
    }
}
