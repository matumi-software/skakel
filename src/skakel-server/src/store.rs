//! What the server keeps between runs, and where it keeps it.

use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// What a store returns: an I/O result, boxed so a store can sit behind `dyn`.
pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send + 'a>>;

/// Where the server keeps its state: its clients, its signing keys and its certificates. The
/// app supplies one. [`InMemoryStore`] keeps nothing past the process; [`FileStore`] writes a JSON
/// file.
///
/// The state holds private keys and the hashes of client secrets, so a store should keep it where
/// only the server's own account can read it.
pub trait SkakelStore: Send + Sync + 'static {
    /// The saved state, or `None` the first time, when the server makes its keys and certificate.
    fn load(&self) -> StoreFuture<'_, Option<SkakelState>>;

    /// Saves the state, replacing the last. The server calls it before it acts on a change, so a
    /// failure leaves the change undone.
    fn save<'a>(&'a self, state: &'a SkakelState) -> StoreFuture<'a, ()>;
}

/// A shared store is a store, so the app can keep a handle to the one it gave the server.
impl<T: SkakelStore> SkakelStore for std::sync::Arc<T> {
    fn load(&self) -> StoreFuture<'_, Option<SkakelState>> {
        (**self).load()
    }

    fn save<'a>(&'a self, state: &'a SkakelState) -> StoreFuture<'a, ()> {
        (**self).save(state)
    }
}

/// Everything the server persists.
///
/// The JSON the file store writes is this type's own. It is not the state the .NET server of
/// Skakel 0.1 kept, which held its certificates as PFX, so that state does not load here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SkakelState {
    /// The registered clients.
    pub clients: Vec<ClientRecord>,
    /// The key that signs access tokens.
    pub signing_key: KeyRecord,
    /// Keys that were replaced but whose tokens are still live.
    #[serde(default)]
    pub retired_signing_keys: Vec<KeyRecord>,
    /// The certificate the server presents.
    pub certificate: CertificateRecord,
    /// The certificate the server will present next, while a handover is under way.
    #[serde(default)]
    pub next_certificate: Option<NextCertificateRecord>,
}

/// A registered client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientRecord {
    /// The client's id, such as `client-3fa9c01b2e`.
    pub id: String,
    /// The name the person saw when they approved it.
    pub name: String,
    /// `sha256$` and the base64 of the SHA-256 of its secret.
    pub secret_hash: String,
    /// When it was registered.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Raised each time the secret is rotated; tokens of an older generation are refused.
    pub generation: u32,
    /// The secret itself, kept only when the server was told to (an app that shows it again).
    #[serde(default)]
    pub secret: Option<String>,
}

/// A token signing key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyRecord {
    /// The id in the `kid` header of the tokens it signs.
    pub key_id: String,
    /// The ECDSA P-256 private key, PKCS#8 DER as base64.
    pub private_key: String,
    /// When it was made.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// For a replaced key, until when tokens it signed are still taken.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub accept_until: Option<OffsetDateTime>,
}

/// A certificate and its private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateRecord {
    /// The certificate, DER as base64.
    pub certificate: String,
    /// Its ECDSA P-256 private key, PKCS#8 DER as base64.
    pub private_key: String,
}

/// A certificate prepared for a handover.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NextCertificateRecord {
    /// The next certificate and its key.
    pub certificate: CertificateRecord,
    /// When it was prepared.
    #[serde(with = "time::serde::rfc3339")]
    pub prepared_at: OffsetDateTime,
    /// The ids of the clients that said they stored it.
    #[serde(default)]
    pub received_by: Vec<String>,
}

/// Keeps the state in memory only. Good for tests and for a server whose clients need not survive
/// a restart.
#[derive(Debug, Default)]
pub struct InMemoryStore {
    state: Mutex<Option<SkakelState>>,
}

impl InMemoryStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// What was saved last.
    pub fn state(&self) -> Option<SkakelState> {
        self.state.lock().expect("store lock").clone()
    }
}

impl SkakelStore for InMemoryStore {
    fn load(&self) -> StoreFuture<'_, Option<SkakelState>> {
        Box::pin(async move { Ok(self.state()) })
    }

    fn save<'a>(&'a self, state: &'a SkakelState) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            *self.state.lock().expect("store lock") = Some(state.clone());
            Ok(())
        })
    }
}

/// Keeps the state in one JSON file, written to a temporary file and renamed over the old one so
/// a crash never leaves half a state.
#[derive(Debug, Clone)]
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    /// A store in the file at `path`. The file and its folder are made on the first save.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl SkakelStore for FileStore {
    fn load(&self) -> StoreFuture<'_, Option<SkakelState>> {
        Box::pin(async move {
            match tokio::fs::read(&self.path).await {
                Ok(bytes) => serde_json::from_slice(&bytes)
                    .map(Some)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error),
            }
        })
    }

    fn save<'a>(&'a self, state: &'a SkakelState) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            let json = serde_json::to_vec_pretty(state).map_err(io::Error::other)?;
            if let Some(folder) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
                tokio::fs::create_dir_all(folder).await?;
            }
            let mut temporary = self.path.clone().into_os_string();
            temporary.push(".tmp");
            let temporary = PathBuf::from(temporary);
            tokio::fs::write(&temporary, json).await?;
            tokio::fs::rename(&temporary, &self.path).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> SkakelState {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        SkakelState {
            clients: vec![ClientRecord {
                id: "client-1".into(),
                name: "lab pc".into(),
                secret_hash: "sha256$x".into(),
                created_at: now,
                generation: 2,
                secret: None,
            }],
            signing_key: KeyRecord {
                key_id: "skakel-1".into(),
                private_key: "AA==".into(),
                created_at: now,
                accept_until: None,
            },
            retired_signing_keys: vec![],
            certificate: CertificateRecord {
                certificate: "AA==".into(),
                private_key: "AA==".into(),
            },
            next_certificate: None,
        }
    }

    #[tokio::test]
    async fn the_memory_store_gives_back_what_was_saved() {
        let store = InMemoryStore::new();
        assert_eq!(store.load().await.unwrap(), None);

        store.save(&state()).await.unwrap();

        assert_eq!(store.load().await.unwrap(), Some(state()));
    }

    #[tokio::test]
    async fn the_file_store_round_trips_and_makes_its_folder() {
        let folder =
            std::env::temp_dir().join(format!("skakel-store-{}", crate::util::new_id("t")));
        let store = FileStore::new(folder.join("nested").join("state.json"));
        assert_eq!(store.load().await.unwrap(), None);

        store.save(&state()).await.unwrap();
        store.save(&state()).await.unwrap();

        assert_eq!(store.load().await.unwrap(), Some(state()));
        assert!(!folder.join("nested").join("state.json.tmp").exists());
        let _ = std::fs::remove_dir_all(folder);
    }

    #[tokio::test]
    async fn the_file_store_says_so_when_the_file_is_not_json() {
        let folder =
            std::env::temp_dir().join(format!("skakel-store-{}", crate::util::new_id("t")));
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(folder.join("state.json"), b"not json").unwrap();

        let error = FileStore::new(folder.join("state.json"))
            .load()
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let _ = std::fs::remove_dir_all(folder);
    }
}
