//! What an app can name and match on, as an app outside the crate sees it.

use skakel_server::{CryptoError, ServerError, StreamOpen};

#[test]
fn a_crypto_error_can_be_named_and_is_an_error() {
    fn is_error<E: std::error::Error + Send + Sync + 'static>() {}
    is_error::<CryptoError>();

    let matches_crypto = |error: &ServerError| matches!(error, ServerError::Crypto(_));
    let invalid = ServerError::Invalid("no".into());
    assert!(!matches_crypto(&invalid));
}

#[test]
fn the_enums_an_app_matches_on_can_grow_so_a_match_needs_a_wildcard() {
    let open = StreamOpen::NotFound("no such port".into());

    let words = match open {
        StreamOpen::NotFound(words) | StreamOpen::InUse(words) | StreamOpen::BadTarget(words) => {
            words
        }
        _ => String::new(),
    };

    assert_eq!(words, "no such port");
}
