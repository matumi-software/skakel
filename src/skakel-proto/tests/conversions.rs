//! The conversions between the generated messages and `skakel-wire`'s types: what the control
//! channel's closing reasons mean, and the hello answer.

use skakel_proto::closing_reason;
use skakel_proto::v2::{ClosingReason, HelloResponse};
use skakel_wire::{Reason, SkakelHello};

#[test]
fn revoked_and_rotated_are_their_own_closing_reasons_and_every_other_reason_is_stopping() {
    assert_eq!(ClosingReason::from(Reason::Revoked), ClosingReason::Revoked);
    assert_eq!(ClosingReason::from(Reason::Rotated), ClosingReason::Rotated);
    for reason in Reason::ALL {
        if !matches!(reason, Reason::Revoked | Reason::Rotated) {
            assert_eq!(
                ClosingReason::from(*reason),
                ClosingReason::Stopping,
                "{reason}"
            );
        }
    }
}

#[test]
fn a_closing_reason_this_end_does_not_know_counts_as_stopping() {
    assert_eq!(
        closing_reason(ClosingReason::Revoked as i32),
        Reason::Revoked
    );
    assert_eq!(
        closing_reason(ClosingReason::Rotated as i32),
        Reason::Rotated
    );
    assert_eq!(
        closing_reason(ClosingReason::Stopping as i32),
        Reason::Stopping
    );
    assert_eq!(
        closing_reason(ClosingReason::Unspecified as i32),
        Reason::Stopping
    );
    assert_eq!(closing_reason(1000), Reason::Stopping);
    assert_eq!(closing_reason(-1), Reason::Stopping);
}

#[test]
fn a_hello_answer_and_the_apps_hello_convert_both_ways() {
    let answer = HelloResponse {
        server: "pi-lab".into(),
        client_id: "c1".into(),
    };
    let hello = SkakelHello::from(answer.clone());
    assert_eq!(hello.server, "pi-lab");
    assert_eq!(hello.client_id, "c1");
    assert_eq!(HelloResponse::from(hello), answer);
}
