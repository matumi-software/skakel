//! What an app can name and match on, as an app outside the crate sees it.

use skakel_server::{CryptoError, ServerError, StreamOpen};

#[test]
fn a_crypto_error_can_be_named_and_is_an_error() {
    fn is_error<E: std::error::Error + Send + Sync + 'static>() {}
    is_error::<CryptoError>();

    let matches_crypto = |error: &ServerError| matches!(error, ServerError::Crypto(_));
    let invalid = ServerError::InvalidName;
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

#[test]
fn an_error_says_what_was_wrong_and_keeps_its_cause() {
    use skakel_server::{OptionProblem, StateError};
    use std::error::Error;

    let tls = ServerError::Tls(Box::new(std::io::Error::other("no protocol versions")));
    assert!(tls.to_string().contains("no protocol versions"), "{tls}");
    assert!(tls.source().is_some());

    let state = ServerError::State(StateError::NotBase64(Box::new(std::io::Error::other("x"))));
    assert!(
        state
            .to_string()
            .starts_with("a saved certificate or key is not base64")
    );
    assert!(state.source().and_then(|s| s.source()).is_some());

    let options = ServerError::Options(vec![OptionProblem::AppId, OptionProblem::Name]);
    assert_eq!(
        options.to_string(),
        "invalid options: The app id must be 1 to 32 of a-z, 0-9 and -. The name must not be empty."
    );
    let reason = ServerError::InvalidReason("lower".into());
    assert!(reason.to_string().contains("'lower'"));
}

#[test]
fn an_app_can_implement_a_stream_handler_on_a_type_of_its_own() {
    use skakel_server::{InMemoryStore, SkakelServerBuilder, StreamHandler, StreamRequest};

    struct Refuse;
    impl StreamHandler for Refuse {
        async fn open(&self, _request: StreamRequest) -> StreamOpen {
            StreamOpen::BadTarget("never".into())
        }
    }

    let _ = SkakelServerBuilder::new("my-app", "1.0.0", InMemoryStore::new())
        .stream("refuse", Refuse)
        .stream("closure", |_request: StreamRequest| async {
            StreamOpen::NotFound("nothing".into())
        });
}
