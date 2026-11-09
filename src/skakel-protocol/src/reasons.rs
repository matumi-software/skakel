//! Why a gRPC call was refused or ended: the reasons of `docs/protocol.md` ("Errors on gRPC calls"),
//! each with the status code it goes with. A refusal carries the code and, in a
//! `google.rpc.ErrorInfo`, the domain [`ERROR_DOMAIN`] and the reason's word.

/// The `ErrorInfo` domain of every reason Skakel itself gives.
pub const ERROR_DOMAIN: &str = "skakel";

/// What the domain of a stream type's own reasons starts with, as in `skakel.streams.serial`.
pub const STREAM_TYPE_DOMAIN_PREFIX: &str = "skakel.streams.";

/// The gRPC status code a stream type ends a stream with for a reason of its own: `ABORTED`.
pub const STREAM_TYPE_CODE: i32 = 10;

/// The most characters a reason has.
pub const MAX_REASON_LENGTH: usize = 63;

/// The `ErrorInfo` domain of a stream type's own reasons.
pub fn stream_type_domain(stream_type: &str) -> String {
    format!("{STREAM_TYPE_DOMAIN_PREFIX}{stream_type}")
}

/// True for a reason a stream type may define: upper case letters, digits and `_`, starting with a
/// letter, at most 63 characters.
pub fn is_reason(text: &str) -> bool {
    let mut chars = text.chars();
    chars.next().is_some_and(|c| c.is_ascii_uppercase())
        && text.len() <= MAX_REASON_LENGTH
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// A reason Skakel gives for refusing or ending a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// A call started with no token, an expired one, one the server did not sign, or one from an
    /// older generation or a removed client.
    TokenRefused,
    /// The control call reached the end of the token it was opened with.
    TokenExpired,
    /// The client was revoked.
    Revoked,
    /// The client's secret was rotated.
    Rotated,
    /// The server is stopping, or no longer serves this stream type.
    Stopping,
    /// A stream's first frame is not `open`, its type breaks the rule, or no `open` came in time.
    BadOpen,
    /// A frame where the stream does not allow one.
    BadFrame,
    /// The server has no such stream type.
    NoSuchType,
    /// The server has no such target.
    NoSuchTarget,
    /// The target is in use.
    InUse,
    /// The stream's target is not what the type expects.
    BadTarget,
    /// After `opened`: the target went away.
    TargetGone,
}

impl Reason {
    /// Every reason, in the order of the protocol's table.
    pub const ALL: [Reason; 12] = [
        Self::TokenRefused,
        Self::TokenExpired,
        Self::Revoked,
        Self::Rotated,
        Self::Stopping,
        Self::BadOpen,
        Self::BadFrame,
        Self::NoSuchType,
        Self::NoSuchTarget,
        Self::InUse,
        Self::BadTarget,
        Self::TargetGone,
    ];

    /// The reason's word, as `ErrorInfo.reason` carries it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TokenRefused => "TOKEN_REFUSED",
            Self::TokenExpired => "TOKEN_EXPIRED",
            Self::Revoked => "REVOKED",
            Self::Rotated => "ROTATED",
            Self::Stopping => "STOPPING",
            Self::BadOpen => "BAD_OPEN",
            Self::BadFrame => "BAD_FRAME",
            Self::NoSuchType => "NO_SUCH_TYPE",
            Self::NoSuchTarget => "NO_SUCH_TARGET",
            Self::InUse => "IN_USE",
            Self::BadTarget => "BAD_TARGET",
            Self::TargetGone => "TARGET_GONE",
        }
    }

    /// The reason for a word, or `None` for one Skakel does not give.
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|reason| reason.as_str() == text)
    }

    /// The gRPC status code the reason goes with, as its number: `UNAUTHENTICATED` (16),
    /// `UNAVAILABLE` (14), `INVALID_ARGUMENT` (3), `NOT_FOUND` (5) or `FAILED_PRECONDITION` (9).
    pub fn code(self) -> i32 {
        match self {
            Self::TokenRefused | Self::TokenExpired | Self::Revoked | Self::Rotated => 16,
            Self::Stopping => 14,
            Self::BadOpen | Self::BadFrame | Self::BadTarget => 3,
            Self::NoSuchType | Self::NoSuchTarget | Self::TargetGone => 5,
            Self::InUse => 9,
        }
    }
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_reason_has_the_word_and_code_of_the_protocols_table() {
        let table: Vec<_> = Reason::ALL.iter().map(|r| (r.as_str(), r.code())).collect();

        assert_eq!(
            table,
            [
                ("TOKEN_REFUSED", 16),
                ("TOKEN_EXPIRED", 16),
                ("REVOKED", 16),
                ("ROTATED", 16),
                ("STOPPING", 14),
                ("BAD_OPEN", 3),
                ("BAD_FRAME", 3),
                ("NO_SUCH_TYPE", 5),
                ("NO_SUCH_TARGET", 5),
                ("IN_USE", 9),
                ("BAD_TARGET", 3),
                ("TARGET_GONE", 5),
            ]
        );
    }

    #[test]
    fn parse_reads_each_word_back_and_nothing_else() {
        for reason in Reason::ALL {
            assert_eq!(Reason::parse(reason.as_str()), Some(reason));
            assert!(is_reason(reason.as_str()));
        }
        assert_eq!(Reason::parse("token_refused"), None);
        assert_eq!(Reason::parse("PORT_FAULT"), None);
    }

    #[test]
    fn is_reason_takes_upper_case_digits_and_underscores_from_a_letter() {
        assert!(is_reason("PORT_FAULT"));
        assert!(is_reason("A1"));
        assert!(is_reason(&"A".repeat(63)));
        assert!(!is_reason(&"A".repeat(64)));
        assert!(!is_reason(""));
        assert!(!is_reason("1A"));
        assert!(!is_reason("_A"));
        assert!(!is_reason("Port_fault"));
        assert!(!is_reason("PORT-FAULT"));
    }

    #[test]
    fn a_stream_types_domain_is_under_skakel_streams() {
        assert_eq!(stream_type_domain("serial"), "skakel.streams.serial");
        assert!(stream_type_domain("usb").starts_with(ERROR_DOMAIN));
        assert_eq!(STREAM_TYPE_CODE, 10);
    }
}
