//! The gRPC status code a call ended with, as the type `skakel-wire` defines, so tonic's does
//! not appear in what an app matches on. Only the conversions with tonic's `Code` are here.

use skakel_wire::GrpcCode;
use tonic::Code;

/// The code of tonic's `Code`.
pub(crate) fn grpc_code(code: Code) -> GrpcCode {
    GrpcCode::from_number(code as i32).unwrap_or(GrpcCode::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tonic_code_converts_with_its_wire_number() {
        for number in 0..=16 {
            let code = Code::from_i32(number);
            assert_eq!(grpc_code(code).number(), number);
        }
    }
}
