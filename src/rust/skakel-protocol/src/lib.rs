//! What Skakel clients and servers share. See `docs/protocol.md` at the repository root.
//!
//! For now this holds only the protocol version; the rest follows in its own issue.

/// The protocol version this crate speaks.
pub const VERSION: u32 = 1;

/// The protocol versions this crate speaks, as a server lists them.
pub const VERSIONS: &[u32] = &[VERSION];

/// The unversioned info endpoint: `GET`, no token.
pub const INFO_PATH: &str = "/skakel/info";

/// Every versioned path starts with this.
pub const BASE_PATH: &str = "/skakel/v1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_path_carries_the_version() {
        assert_eq!(BASE_PATH, format!("/skakel/v{VERSION}"));
    }
}
