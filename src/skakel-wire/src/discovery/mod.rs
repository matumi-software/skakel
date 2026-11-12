//! The Skakel discovery packet: the probe, the answer and the limits a client applies. See
//! `docs/protocol.md` ("Discovery") and `docs/parts.md` at the repository root.
//!
//! A client broadcasts a probe over UDP to its app's port; a server answers the client directly
//! with a [`DiscoveryAnswer`]. A probe is padded to [`PROBE_SIZE`] and an answer is never larger
//! than the probe, so nobody can use a server to multiply traffic aimed at someone else.
//!
//! The packets are plain bytes. [`net`] holds the rule for what a server answers. Sockets, which
//! network interfaces to broadcast on, the list of servers found and the limits on it belong to
//! the server and the client.

mod answer;
mod clean;
pub mod net;

pub use answer::{
    AnswerError, DiscoveryAnswer, create_answer, create_probe, is_probe, try_parse_answer,
};
pub use clean::clean;

use std::time::Duration;

/// A probe's size, and the most an answer may take.
pub const PROBE_SIZE: usize = 512;

/// The most characters of a server name a client keeps. Characters are Unicode scalar values, as
/// everywhere in the protocol, so an emoji counts for one.
pub const MAX_NAME_LENGTH: usize = 63;

/// The most characters an app id has.
pub const MAX_APP_ID_LENGTH: usize = crate::MAX_APP_ID_LENGTH;

/// The most characters of an app version a client keeps (Unicode scalar values).
pub const MAX_APP_VERSION_LENGTH: usize = 32;

/// The most protocol versions an answer lists.
pub const MAX_VERSIONS: usize = 8;

/// The most servers a client keeps.
pub const MAX_ENTRIES: usize = 64;

/// The most servers a client keeps from one address.
pub const MAX_ENTRIES_PER_ADDRESS: usize = 8;

/// How often a client probes.
pub const PROBE_INTERVAL: Duration = Duration::from_secs(10);

/// How long a client keeps a server that stopped answering: three missed probes.
pub const ENTRY_LIFETIME: Duration = Duration::from_secs(35);

/// How long after a probe a client takes answers to it.
pub const ANSWER_WINDOW: Duration = Duration::from_secs(3);

/// A probe's first line. The `/1` is the packet layout's own version.
pub const PROBE_LINE: &[u8] = b"SKAKEL-DISCOVER/1\n";

/// An answer's first line. JSON with the server's details follows.
pub const ANSWER_LINE: &[u8] = b"SKAKEL-SERVER/1\n";
