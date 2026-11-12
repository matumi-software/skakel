//! The gRPC status codes, as a type of Skakel's own, so no gRPC library's type is in what an app
//! matches on. The numbers are those of the gRPC specification.

/// A gRPC status code, as in the gRPC specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GrpcCode {
    /// 0, `OK`.
    Ok = 0,
    /// 1, `CANCELLED`.
    Cancelled = 1,
    /// 2, `UNKNOWN`.
    Unknown = 2,
    /// 3, `INVALID_ARGUMENT`.
    InvalidArgument = 3,
    /// 4, `DEADLINE_EXCEEDED`.
    DeadlineExceeded = 4,
    /// 5, `NOT_FOUND`.
    NotFound = 5,
    /// 6, `ALREADY_EXISTS`.
    AlreadyExists = 6,
    /// 7, `PERMISSION_DENIED`.
    PermissionDenied = 7,
    /// 8, `RESOURCE_EXHAUSTED`.
    ResourceExhausted = 8,
    /// 9, `FAILED_PRECONDITION`.
    FailedPrecondition = 9,
    /// 10, `ABORTED`.
    Aborted = 10,
    /// 11, `OUT_OF_RANGE`.
    OutOfRange = 11,
    /// 12, `UNIMPLEMENTED`.
    Unimplemented = 12,
    /// 13, `INTERNAL`.
    Internal = 13,
    /// 14, `UNAVAILABLE`.
    Unavailable = 14,
    /// 15, `DATA_LOSS`.
    DataLoss = 15,
    /// 16, `UNAUTHENTICATED`.
    Unauthenticated = 16,
}

impl GrpcCode {
    /// The code's number on the wire.
    pub fn number(self) -> i32 {
        self as i32
    }

    /// The code for a number on the wire, or `None` for one the specification does not give.
    pub fn from_number(number: i32) -> Option<Self> {
        match number {
            0 => Some(Self::Ok),
            1 => Some(Self::Cancelled),
            2 => Some(Self::Unknown),
            3 => Some(Self::InvalidArgument),
            4 => Some(Self::DeadlineExceeded),
            5 => Some(Self::NotFound),
            6 => Some(Self::AlreadyExists),
            7 => Some(Self::PermissionDenied),
            8 => Some(Self::ResourceExhausted),
            9 => Some(Self::FailedPrecondition),
            10 => Some(Self::Aborted),
            11 => Some(Self::OutOfRange),
            12 => Some(Self::Unimplemented),
            13 => Some(Self::Internal),
            14 => Some(Self::Unavailable),
            15 => Some(Self::DataLoss),
            16 => Some(Self::Unauthenticated),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_number_of_the_specification_converts_both_ways() {
        for number in 0..=16 {
            let code = GrpcCode::from_number(number).unwrap();
            assert_eq!(code.number(), number);
        }
        assert_eq!(GrpcCode::from_number(-1), None);
        assert_eq!(GrpcCode::from_number(17), None);
    }

    #[test]
    fn the_codes_skakel_uses_have_their_numbers() {
        assert_eq!(GrpcCode::Aborted.number(), 10);
        assert_eq!(GrpcCode::Unavailable.number(), 14);
        assert_eq!(GrpcCode::Unauthenticated.number(), 16);
    }
}
