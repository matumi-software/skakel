//! The JSON bodies the protocol defines outside pairing: info, and what `ControlService.Hello`
//! answers.

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
    pub versions: Vec<u32>,
}

/// What `ControlService.Hello` answers to a token that works: who the server is and whom the token
/// belongs to. Written as JSON in camelCase for an app that passes it on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SkakelHello {
    /// The server's name.
    pub server: String,
    /// The client the token was issued to.
    pub client_id: String,
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
    fn info_versions_are_unsigned_so_a_negative_one_does_not_read() {
        let negative = r#"{"name":"x","app":{"id":"a","version":"1"},"versions":[-1]}"#;

        assert!(serde_json::from_str::<SkakelInfo>(negative).is_err());
    }

    #[test]
    fn info_is_written_in_the_pinned_order() {
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
}
