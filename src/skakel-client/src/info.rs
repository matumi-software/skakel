//! Reading a server's `GET /skakel/info`, and picking the protocol version to speak with it.

use skakel_discovery::{MAX_APP_VERSION_LENGTH, MAX_NAME_LENGTH, MAX_VERSIONS, clean};
use skakel_protocol::{INFO_PATH, SkakelApp, SkakelInfo, VERSIONS, is_app_id};
use url::Url;

use crate::failure::{Error, Failure, Result, bad_answer};
use crate::http::{self, base_address};
use crate::options::ClientOptions;
use crate::pins::Pins;
use crate::request::HttpClient;

/// The highest version both this client and the server speak, or `None` when there is none.
///
/// `server_versions` are the versions the server listed, from discovery or `/skakel/info`.
pub fn pick_version(server_versions: &[u32]) -> Option<u32> {
    VERSIONS
        .iter()
        .copied()
        .filter(|v| server_versions.contains(v))
        .max()
}

/// The version to speak. A [`FailureKind::VersionMismatch`](crate::FailureKind::VersionMismatch)
/// that names both sides' versions when there is none.
pub fn require_version(server_versions: &[u32]) -> Result<u32> {
    pick_version(server_versions)
        .ok_or_else(|| Error::new(Failure::version_mismatch(server_versions)))
}

/// Reads a server's `GET /skakel/info`: its name, its app and the protocol versions it speaks. Over
/// a connection pinned to the server's fingerprints, so any answer also proves the server holds one
/// of those certificates. The answer is held to the limits discovery applies: the name and app
/// version cleaned and cut as [`clean`] does, the app id a real one, and at most 64 KB read.
///
/// This does not check the version, so an app can still show the server's name when there is none;
/// pick it with [`require_version`].
pub async fn read_info(address: &Url, pins: &Pins, options: &ClientOptions) -> Result<SkakelInfo> {
    let server = base_address(address)?;
    let client = HttpClient::pinned(pins.clone());
    read_info_with(&client, &server, options.request_timeout).await
}

/// The same over a client the caller made, pinned.
pub(crate) async fn read_info_with(
    client: &HttpClient,
    server: &Url,
    timeout: std::time::Duration,
) -> Result<SkakelInfo> {
    let result = async {
        let url = server.join(INFO_PATH).map_err(Error::from_cause)?;
        let response = client.get(url).timeout(timeout).send().await?;
        let info: SkakelInfo = response.read_json()?;
        check(info, server)
    }
    .await;
    if let Err(error) = &result {
        log::info!(
            "Could not read the info of {}: {error:?}",
            http::authority(server)
        );
    }
    result
}

fn check(info: SkakelInfo, server: &Url) -> Result<SkakelInfo> {
    let SkakelInfo {
        name,
        app,
        versions,
    } = info;
    if app.version.encode_utf16().count() > MAX_APP_VERSION_LENGTH
        || !is_app_id(&app.id)
        || !(1..=MAX_VERSIONS).contains(&versions.len())
        || versions.contains(&0)
    {
        return Err(bad_answer(
            "The info answer is missing the name, the app or the versions, or breaks their limits.",
        ));
    }
    // The same limits as discovery: a name a person can be shown, the address when that leaves nothing.
    let shown = clean(&name, MAX_NAME_LENGTH);
    Ok(SkakelInfo {
        name: if shown.is_empty() {
            server.host_str().unwrap_or_default().to_owned()
        } else {
            shown
        },
        app: SkakelApp {
            id: app.id,
            version: clean(&app.version, MAX_APP_VERSION_LENGTH),
        },
        versions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::failure::FailureKind;

    fn info(name: &str, id: &str, version: &str, versions: Vec<u32>) -> SkakelInfo {
        SkakelInfo {
            name: name.into(),
            app: SkakelApp {
                id: id.into(),
                version: version.into(),
            },
            versions,
        }
    }

    fn server() -> Url {
        Url::parse("https://10.0.0.5:5240/").unwrap()
    }

    #[test]
    fn pick_version_takes_the_highest_both_speak() {
        assert_eq!(pick_version(&[2]), Some(2));
        assert_eq!(pick_version(&[3, 2, 1]), Some(2));
        assert_eq!(pick_version(&[1]), None);
        assert_eq!(pick_version(&[3, 4]), None);
        assert_eq!(pick_version(&[]), None);
    }

    #[test]
    fn require_version_names_both_sides_when_there_is_none() {
        let error = require_version(&[1]).unwrap_err();

        assert_eq!(error.kind(), FailureKind::VersionMismatch);
        assert_eq!(
            error.to_string(),
            "This server speaks Skakel 1 and this app speaks Skakel 2. Update the server."
        );
    }

    #[test]
    fn check_cleans_the_name_and_the_version() {
        let checked = check(
            info(" pi\u{202E}lab ", "koppel", "1.0\u{200B}", vec![2]),
            &server(),
        )
        .unwrap();

        assert_eq!(checked.name, "pilab");
        assert_eq!(checked.app.version, "1.0");
    }

    #[test]
    fn check_puts_the_address_in_for_a_name_that_is_nothing_once_cleaned() {
        let checked = check(info("\u{200B}", "koppel", "1", vec![2]), &server()).unwrap();

        assert_eq!(checked.name, "10.0.0.5");
    }

    #[test]
    fn check_refuses_what_breaks_the_limits() {
        let long_version = "v".repeat(33);
        let bad = [
            info("x", "Koppel", "1", vec![2]),
            info("x", "", "1", vec![2]),
            info("x", "koppel", &long_version, vec![2]),
            info("x", "koppel", "1", vec![]),
            info("x", "koppel", "1", vec![0]),
            info("x", "koppel", "1", vec![2; 9]),
        ];

        for case in bad {
            assert_eq!(
                check(case, &server()).unwrap_err().kind(),
                FailureKind::UnexpectedAnswer
            );
        }
    }
}
