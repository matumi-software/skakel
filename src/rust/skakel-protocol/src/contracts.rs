//! The JSON bodies the protocol defines outside pairing: info, hello and a refusal's problem body.

use serde::{Deserialize, Serialize};

/// The app a server belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkakelApp {
    /// 1 to 32 of `a-z`, `0-9` and `-`, such as `koppel`.
    pub id: String,
    /// The app's own version, at most 32 characters.
    pub version: String,
}

/// What `GET /skakel/info` answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkakelInfo {
    /// The server's name, as discovery gives it.
    pub name: String,
    /// The app the server belongs to.
    pub app: SkakelApp,
    /// The protocol versions the server speaks.
    pub versions: Vec<i32>,
}

/// What `GET /skakel/v1/hello` answers to a token that works.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SkakelHello {
    /// The server's name.
    pub server: String,
    /// The client the token was issued to.
    pub client_id: String,
}

/// The body of a refusal, sent as `application/problem+json` (RFC 9457). `detail` is written for a
/// person to read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkakelProblem {
    /// A URI for the kind of problem, often `about:blank` or a link to the HTTP status. `type` on
    /// the wire.
    #[serde(rename = "type", default)]
    pub kind: Option<String>,
    /// A short summary of the kind of problem.
    #[serde(default)]
    pub title: Option<String>,
    /// The HTTP status code.
    #[serde(default)]
    pub status: Option<i32>,
    /// What went wrong this time, for a person.
    #[serde(default)]
    pub detail: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_reads_what_the_protocol_shows() {
        let info: SkakelInfo = serde_json::from_str(
            r#"{"name":"pi-lab","app":{"id":"koppel","version":"0.1.1"},"versions":[1]}"#,
        )
        .unwrap();

        assert_eq!(info.name, "pi-lab");
        assert_eq!(info.app.id, "koppel");
        assert_eq!(info.versions, [1]);
    }

    #[test]
    fn info_is_written_in_the_order_dotnet_writes_it() {
        let info = SkakelInfo {
            name: "pi-lab".into(),
            app: SkakelApp {
                id: "koppel".into(),
                version: "0.1.1".into(),
            },
            versions: vec![1],
        };

        assert_eq!(
            serde_json::to_string(&info).unwrap(),
            r#"{"name":"pi-lab","app":{"id":"koppel","version":"0.1.1"},"versions":[1]}"#
        );
    }

    #[test]
    fn hello_uses_camel_case() {
        let hello = SkakelHello {
            server: "pi-lab".into(),
            client_id: "c1".into(),
        };

        assert_eq!(
            serde_json::to_string(&hello).unwrap(),
            r#"{"server":"pi-lab","clientId":"c1"}"#
        );
        assert_eq!(
            serde_json::from_str::<SkakelHello>(r#"{"server":"pi-lab","clientId":"c1"}"#).unwrap(),
            hello
        );
    }

    #[test]
    fn problem_reads_the_fields_that_are_there() {
        let problem: SkakelProblem = serde_json::from_str(
            r#"{"type":"about:blank","title":"Conflict","status":409,"detail":"In use"}"#,
        )
        .unwrap();

        assert_eq!(problem.kind.as_deref(), Some("about:blank"));
        assert_eq!(problem.status, Some(409));
        assert_eq!(problem.detail.as_deref(), Some("In use"));
    }

    #[test]
    fn problem_takes_fields_that_are_missing_or_null() {
        let problem: SkakelProblem =
            serde_json::from_str(r#"{"status":404,"title":null}"#).unwrap();

        assert_eq!(
            problem,
            SkakelProblem {
                status: Some(404),
                ..SkakelProblem::default()
            }
        );
    }

    #[test]
    fn problem_writes_type_for_its_kind() {
        let problem = SkakelProblem {
            kind: Some("about:blank".into()),
            ..SkakelProblem::default()
        };

        assert_eq!(
            serde_json::to_string(&problem).unwrap(),
            r#"{"type":"about:blank","title":null,"status":null,"detail":null}"#
        );
    }
}
