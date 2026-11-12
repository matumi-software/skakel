//! The gRPC status code a call ended with, as the client's own type, so tonic's does not appear in
//! what an app matches on.

use tonic::Code;

/// A gRPC status code, as in the gRPC specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GrpcCode {
    /// 0, `OK`.
    Ok,
    /// 1, `CANCELLED`.
    Cancelled,
    /// 2, `UNKNOWN`.
    Unknown,
    /// 3, `INVALID_ARGUMENT`.
    InvalidArgument,
    /// 4, `DEADLINE_EXCEEDED`.
    DeadlineExceeded,
    /// 5, `NOT_FOUND`.
    NotFound,
    /// 6, `ALREADY_EXISTS`.
    AlreadyExists,
    /// 7, `PERMISSION_DENIED`.
    PermissionDenied,
    /// 8, `RESOURCE_EXHAUSTED`.
    ResourceExhausted,
    /// 9, `FAILED_PRECONDITION`.
    FailedPrecondition,
    /// 10, `ABORTED`.
    Aborted,
    /// 11, `OUT_OF_RANGE`.
    OutOfRange,
    /// 12, `UNIMPLEMENTED`.
    Unimplemented,
    /// 13, `INTERNAL`.
    Internal,
    /// 14, `UNAVAILABLE`.
    Unavailable,
    /// 15, `DATA_LOSS`.
    DataLoss,
    /// 16, `UNAUTHENTICATED`.
    Unauthenticated,
}

impl GrpcCode {
    /// The code's number on the wire.
    pub fn number(self) -> i32 {
        Code::from(self) as i32
    }
}

impl From<Code> for GrpcCode {
    fn from(code: Code) -> Self {
        match code {
            Code::Ok => Self::Ok,
            Code::Cancelled => Self::Cancelled,
            Code::Unknown => Self::Unknown,
            Code::InvalidArgument => Self::InvalidArgument,
            Code::DeadlineExceeded => Self::DeadlineExceeded,
            Code::NotFound => Self::NotFound,
            Code::AlreadyExists => Self::AlreadyExists,
            Code::PermissionDenied => Self::PermissionDenied,
            Code::ResourceExhausted => Self::ResourceExhausted,
            Code::FailedPrecondition => Self::FailedPrecondition,
            Code::Aborted => Self::Aborted,
            Code::OutOfRange => Self::OutOfRange,
            Code::Unimplemented => Self::Unimplemented,
            Code::Internal => Self::Internal,
            Code::Unavailable => Self::Unavailable,
            Code::DataLoss => Self::DataLoss,
            Code::Unauthenticated => Self::Unauthenticated,
        }
    }
}

impl From<GrpcCode> for Code {
    fn from(code: GrpcCode) -> Self {
        match code {
            GrpcCode::Ok => Self::Ok,
            GrpcCode::Cancelled => Self::Cancelled,
            GrpcCode::Unknown => Self::Unknown,
            GrpcCode::InvalidArgument => Self::InvalidArgument,
            GrpcCode::DeadlineExceeded => Self::DeadlineExceeded,
            GrpcCode::NotFound => Self::NotFound,
            GrpcCode::AlreadyExists => Self::AlreadyExists,
            GrpcCode::PermissionDenied => Self::PermissionDenied,
            GrpcCode::ResourceExhausted => Self::ResourceExhausted,
            GrpcCode::FailedPrecondition => Self::FailedPrecondition,
            GrpcCode::Aborted => Self::Aborted,
            GrpcCode::OutOfRange => Self::OutOfRange,
            GrpcCode::Unimplemented => Self::Unimplemented,
            GrpcCode::Internal => Self::Internal,
            GrpcCode::Unavailable => Self::Unavailable,
            GrpcCode::DataLoss => Self::DataLoss,
            GrpcCode::Unauthenticated => Self::Unauthenticated,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_converts_both_ways_with_its_wire_number() {
        for number in 0..=16 {
            let code = Code::from_i32(number);
            let ours = GrpcCode::from(code);
            assert_eq!(ours.number(), number);
            assert_eq!(Code::from(ours), code);
        }
    }
}
