//! The probe and the answer, as bytes.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::clean::{clean, utf16_len};
use super::{
    ANSWER_LINE, MAX_APP_VERSION_LENGTH, MAX_NAME_LENGTH, MAX_VERSIONS, PROBE_LINE, PROBE_SIZE,
    escape,
};
use crate::{SkakelApp, fingerprints, is_app_id};

/// What a server tells clients that look for it. On the wire these are the fields of the JSON
/// after the answer line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryAnswer {
    /// The name people know the server by.
    pub name: String,
    /// Where its HTTPS listens.
    pub port: u16,
    /// The SHA-256 fingerprint of its certificate, which a client pins when it pairs.
    pub fingerprint: String,
    /// The app the server belongs to.
    pub app: SkakelApp,
    /// The protocol versions it speaks.
    pub versions: Vec<u32>,
}

/// Why [`create_answer`] refused: the answer would be one a client drops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnswerError {
    /// The fingerprint is not 64 hex digits.
    Fingerprint,
    /// The port is 0.
    Port,
    /// The app id is not 1 to 32 of `a-z`, `0-9` and `-`.
    AppId,
    /// There are no versions, more than 8, or one that is 0.
    Versions,
    /// The answer does not fit in a probe even with an empty name.
    TooLarge,
}

impl fmt::Display for AnswerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Fingerprint => "The fingerprint must be 64 hex digits.",
            Self::Port => "The port must be 1 to 65535.",
            Self::AppId => "The app id must be 1 to 32 of a-z, 0-9 and -.",
            Self::Versions => "List 1 to 8 protocol versions, each 1 or more.",
            Self::TooLarge => "The answer does not fit in a probe.",
        })
    }
}

impl std::error::Error for AnswerError {}

/// A probe: the probe line, then zero padding to [`PROBE_SIZE`].
pub fn create_probe() -> Vec<u8> {
    let mut probe = vec![0; PROBE_SIZE];
    probe[..PROBE_LINE.len()].copy_from_slice(PROBE_LINE);
    probe
}

/// True for a datagram a server answers: at least [`PROBE_SIZE`] bytes, starting with the probe
/// line.
pub fn is_probe(datagram: &[u8]) -> bool {
    datagram.len() >= PROBE_SIZE && datagram.starts_with(PROBE_LINE)
}

/// The answer to a probe. The name and the app version are cut to what a client keeps, and the
/// name shortened further if that is what it takes to fit in [`PROBE_SIZE`].
pub fn create_answer(answer: &DiscoveryAnswer) -> Result<Vec<u8>, AnswerError> {
    let fingerprint =
        fingerprints::normalize(&answer.fingerprint).ok_or(AnswerError::Fingerprint)?;
    if answer.port == 0 {
        return Err(AnswerError::Port);
    }
    if !is_app_id(&answer.app.id) {
        return Err(AnswerError::AppId);
    }
    if !(1..=MAX_VERSIONS).contains(&answer.versions.len()) || answer.versions.contains(&0) {
        return Err(AnswerError::Versions);
    }

    let mut body = DiscoveryAnswer {
        name: clean(&answer.name, MAX_NAME_LENGTH),
        port: answer.port,
        fingerprint,
        app: SkakelApp {
            id: answer.app.id.clone(),
            version: clean(&answer.app.version, MAX_APP_VERSION_LENGTH),
        },
        versions: answer.versions.clone(),
    };
    loop {
        let json = escape::to_vec(&body);
        if ANSWER_LINE.len() + json.len() <= PROBE_SIZE {
            return Ok([ANSWER_LINE, &json].concat());
        }
        // Only a name full of characters that take many bytes each gets here.
        if body.name.pop().is_none() {
            return Err(AnswerError::TooLarge);
        }
    }
}

/// Reads an answer, applying the limits a client applies. `None` for anything else: a wrong first
/// line, broken JSON, a fingerprint that is not 64 hex digits, a port of 0, a name over 63
/// characters, an app id that is not one, an app version over 32 characters, or no versions or
/// more than 8. Control and format characters in the name and version are dropped (see [`clean`]).
/// The fingerprint comes back in colon form.
pub fn try_parse_answer(datagram: &[u8]) -> Option<DiscoveryAnswer> {
    let json = datagram.strip_prefix(ANSWER_LINE)?;
    let body: DiscoveryAnswer = serde_json::from_slice(json).ok()?;
    let fingerprint = fingerprints::normalize(&body.fingerprint)?;
    if body.port == 0
        || utf16_len(&body.name) > MAX_NAME_LENGTH
        || utf16_len(&body.app.version) > MAX_APP_VERSION_LENGTH
        || !is_app_id(&body.app.id)
        || !(1..=MAX_VERSIONS).contains(&body.versions.len())
        || body.versions.contains(&0)
    {
        return None;
    }
    Some(DiscoveryAnswer {
        name: clean(&body.name, MAX_NAME_LENGTH),
        fingerprint,
        app: SkakelApp {
            id: body.app.id,
            version: clean(&body.app.version, MAX_APP_VERSION_LENGTH),
        },
        ..body
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FINGERPRINT: &str = "EF:EF:EF:EF:EF:EF:EF:EF:EF:EF:EF:EF:EF:EF:EF:EF:EF:EF:EF:EF:EF:EF:EF:EF:EF:EF:EF:EF:EF:EF:EF:EF";

    fn answer(name: &str, version: &str, app_id: &str) -> DiscoveryAnswer {
        DiscoveryAnswer {
            name: name.into(),
            port: 5240,
            fingerprint: FINGERPRINT.into(),
            app: SkakelApp {
                id: app_id.into(),
                version: version.into(),
            },
            versions: vec![1],
        }
    }

    fn standard() -> DiscoveryAnswer {
        answer("pi-lab", "0.1.1", "koppel")
    }

    fn fingerprint_json() -> String {
        format!(r#""fingerprint":"{FINGERPRINT}""#)
    }

    #[test]
    fn create_probe_is_the_probe_line_and_zero_padding_to_512_bytes() {
        let probe = create_probe();

        assert_eq!(probe.len(), 512);
        assert_eq!(&probe[..18], b"SKAKEL-DISCOVER/1\n");
        assert!(probe[18..].iter().all(|b| *b == 0));
    }

    #[test]
    fn is_probe_wants_the_line_and_at_least_512_bytes() {
        let mut longer = create_probe();
        longer.push(0);
        let mut koppel = vec![0; 512];
        koppel[..18].copy_from_slice(b"KOPPEL-DISCOVER/1\n");

        assert!(is_probe(&create_probe()));
        assert!(is_probe(&longer));
        assert!(!is_probe(&create_probe()[..511]));
        assert!(!is_probe(&koppel), "version 0 probes are not answered");
    }

    #[test]
    fn create_answer_writes_the_pinned_bytes() {
        let expected = format!(
            "SKAKEL-SERVER/1\n{{\"name\":\"pi-lab\",\"port\":5240,{},\"app\":{{\"id\":\"koppel\",\"version\":\"0.1.1\"}},\"versions\":[1]}}",
            fingerprint_json()
        );

        assert_eq!(create_answer(&standard()).unwrap(), expected.as_bytes());
    }

    #[test]
    fn create_answer_cleans_normalises_and_escapes() {
        let given = DiscoveryAnswer {
            name: "  pi\u{202E}lab \u{1F600}\n".into(),
            port: 65535,
            fingerprint: FINGERPRINT.to_ascii_lowercase().replace(':', ""),
            app: SkakelApp {
                id: "a-1".into(),
                version: "1.0\u{200B}".into(),
            },
            versions: vec![1, 2, 3, 4, 5, 6, 7, 8],
        };
        let expected = format!(
            "SKAKEL-SERVER/1\n{{\"name\":\"pilab \\uD83D\\uDE00\",\"port\":65535,{},\"app\":{{\"id\":\"a-1\",\"version\":\"1.0\"}},\"versions\":[1,2,3,4,5,6,7,8]}}",
            fingerprint_json()
        );

        assert_eq!(create_answer(&given).unwrap(), expected.as_bytes());
    }

    #[test]
    fn create_answer_cuts_a_long_name_at_the_pinned_place() {
        // Name and version of 200 characters each and an app id of 32: what is left of the name
        // after the answer is made to fit, per character, with the byte count it comes to.
        let cases = [
            ("a", 63, 322),
            ("\u{E9}", 63, 417),
            ("\u{1F600}", 7, 503),
            ("\"", 63, 417),
        ];

        for (character, name_chars, bytes) in cases {
            let long = character.repeat(200);
            let created = create_answer(&answer(&long, &long, &"z".repeat(32))).unwrap();
            let parsed = try_parse_answer(&created).unwrap();

            assert_eq!(created.len(), bytes, "{character}");
            assert_eq!(parsed.name.chars().count(), name_chars, "{character}");
        }
    }

    #[test]
    fn create_answer_always_fits_in_a_probe() {
        for character in ["a", "\u{E9}", "\u{1F600}", "\"", "\u{4E2D}", "\u{00A0}x"] {
            let long = character.repeat(200);

            let created = create_answer(&answer(&long, &long, &"z".repeat(32))).unwrap();

            assert!(created.len() <= PROBE_SIZE, "{character}");
            assert!(try_parse_answer(&created).is_some(), "{character}");
        }
    }

    #[test]
    fn create_answer_refuses_what_a_client_would_drop() {
        let mut bad_fingerprint = standard();
        bad_fingerprint.fingerprint = "AB".into();
        let mut bad_port = standard();
        bad_port.port = 0;
        let mut no_versions = standard();
        no_versions.versions = vec![];
        let mut too_many = standard();
        too_many.versions = vec![1; 9];
        let mut zero_version = standard();
        zero_version.versions = vec![0];

        assert_eq!(
            create_answer(&bad_fingerprint),
            Err(AnswerError::Fingerprint)
        );
        assert_eq!(
            create_answer(&answer("x", "1", "Koppel")),
            Err(AnswerError::AppId)
        );
        assert_eq!(create_answer(&bad_port), Err(AnswerError::Port));
        assert_eq!(create_answer(&no_versions), Err(AnswerError::Versions));
        assert_eq!(create_answer(&too_many), Err(AnswerError::Versions));
        assert_eq!(create_answer(&zero_version), Err(AnswerError::Versions));
    }

    #[test]
    fn try_parse_answer_reads_what_create_answer_wrote() {
        let parsed = try_parse_answer(&create_answer(&standard()).unwrap());

        assert_eq!(parsed, Some(standard()));
    }

    #[test]
    fn try_parse_answer_drops_an_answer_outside_the_limits() {
        let fp = FINGERPRINT;
        let app = r#""app":{"id":"koppel","version":"1"}"#;
        let bodies = [
            format!(r#"{{"name":"x","port":5240,"fingerprint":"AB",{app},"versions":[1]}}"#),
            format!(r#"{{"name":"x","port":0,"fingerprint":"{fp}",{app},"versions":[1]}}"#),
            format!(r#"{{"name":"x","port":70000,"fingerprint":"{fp}",{app},"versions":[1]}}"#),
            format!(
                r#"{{"name":"x","port":5240,"fingerprint":"{fp}","app":{{"id":"Koppel","version":"1"}},"versions":[1]}}"#
            ),
            format!(r#"{{"name":"x","port":5240,"fingerprint":"{fp}",{app},"versions":[]}}"#),
            format!(
                r#"{{"name":"x","port":5240,"fingerprint":"{fp}",{app},"versions":[1,2,3,4,5,6,7,8,9]}}"#
            ),
            format!(r#"{{"name":"x","port":5240,"fingerprint":"{fp}",{app},"versions":[0]}}"#),
            format!(r#"{{"name":"x","port":5240,"fingerprint":"{fp}","versions":[1]}}"#),
            format!(r#"{{"port":5240,"fingerprint":"{fp}",{app},"versions":[1]}}"#),
            format!(r#"{{"name":null,"port":5240,"fingerprint":"{fp}",{app},"versions":[1]}}"#),
            "not json".to_owned(),
            "null".to_owned(),
        ];

        for body in bodies {
            let datagram = format!("SKAKEL-SERVER/1\n{body}");
            assert_eq!(try_parse_answer(datagram.as_bytes()), None, "{body}");
        }
    }

    #[test]
    fn try_parse_answer_drops_a_long_name_or_version_and_a_wrong_first_line() {
        let long_name = serde_json::to_string(&answer(&"n".repeat(64), "1", "koppel")).unwrap();
        let long_version = serde_json::to_string(&answer("x", &"v".repeat(33), "koppel")).unwrap();
        let koppel = serde_json::to_string(&standard()).unwrap();

        assert_eq!(
            try_parse_answer(format!("SKAKEL-SERVER/1\n{long_name}").as_bytes()),
            None
        );
        assert_eq!(
            try_parse_answer(format!("SKAKEL-SERVER/1\n{long_version}").as_bytes()),
            None
        );
        assert_eq!(
            try_parse_answer(format!("KOPPEL-SERVER/1\n{koppel}").as_bytes()),
            None
        );
        assert_eq!(try_parse_answer(koppel.as_bytes()), None);
        assert_eq!(try_parse_answer(b""), None);
    }

    #[test]
    fn try_parse_answer_counts_a_name_in_utf16_units() {
        // 32 emoji are 64 UTF-16 units, one over the limit, though only 32 characters.
        let name = "\u{1F600}".repeat(32);
        let datagram = format!(
            "SKAKEL-SERVER/1\n{}",
            serde_json::to_string(&answer(&name, "1", "koppel")).unwrap()
        );

        assert_eq!(try_parse_answer(datagram.as_bytes()), None);
    }

    #[test]
    fn try_parse_answer_cleans_the_name_and_normalises_the_fingerprint() {
        let datagram = format!(
            "SKAKEL-SERVER/1\n{{\"name\":\" pi\\u202Elab \",\"port\":5240,\"fingerprint\":\"{}\",\"app\":{{\"id\":\"koppel\",\"version\":\"1\\u200B\"}},\"versions\":[1]}}",
            "ef".repeat(32)
        );

        let parsed = try_parse_answer(datagram.as_bytes()).unwrap();

        assert_eq!(parsed.name, "pilab");
        assert_eq!(parsed.fingerprint, FINGERPRINT);
        assert_eq!(parsed.app.version, "1");
    }
}
