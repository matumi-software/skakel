//! The server's live state: its clients, keys and certificates, loaded from the store, changed
//! one write at a time and saved before anything acts on the change.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use skakel_protocol::{ACCESS_TOKEN_LIFETIME, fingerprints};
use time::OffsetDateTime;
use tokio::sync::watch;

use crate::crypto::{self, Principal, Signer, Verifier};
use crate::error::ServerError;
use crate::events::{Events, ServerEvent};
use crate::store::{
    CertificateRecord, ClientRecord, KeyRecord, NextCertificateRecord, SkakelState, SkakelStore,
};
use crate::util;

/// Tokens of a replaced signing key are taken a little past the lifetime of a token.
const RETIRED_KEY_MARGIN: Duration = Duration::from_secs(5 * 60);

/// A client as the app sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientView {
    /// The client's id.
    pub id: String,
    /// The name the person saw when they approved it.
    pub name: String,
    /// When it was registered.
    pub created_at: OffsetDateTime,
    /// When it last got a token.
    pub last_seen: Option<OffsetDateTime>,
    /// Whether it told the server it stored the next certificate.
    pub has_next_certificate: bool,
    /// Whether the server kept its secret (see [`crate::SkakelServerBuilder::keep_client_secrets`]).
    pub has_secret: bool,
}

/// A client that was just registered. The secret is shown here and nowhere again, unless the
/// server was told to keep it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewClient {
    /// The client's id.
    pub client_id: String,
    /// The name it was registered under.
    pub name: String,
    /// The secret.
    pub client_secret: String,
}

/// The certificate and token key now in use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeysView {
    /// The fingerprint of the certificate the server presents.
    pub fingerprint: String,
    /// The fingerprint of the next one, during a handover.
    pub next_fingerprint: Option<String>,
    /// When the next one was prepared.
    pub next_prepared_at: Option<OffsetDateTime>,
    /// The id of the key that signs tokens.
    pub signing_key_id: String,
    /// When that key was made.
    pub signing_key_since: OffsetDateTime,
    /// Until when tokens of replaced keys are still taken.
    pub retired_keys_until: Option<OffsetDateTime>,
}

/// What a certificate switch did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateSwitch {
    /// The fingerprint it switched from.
    pub from: String,
    /// The fingerprint it switched to.
    pub to: String,
    /// The names of the clients that never said they stored the new one; they must pair again.
    pub not_received: Vec<String>,
}

/// The state, with what is made from it for use.
pub(crate) struct Loaded {
    pub state: SkakelState,
    pub certified: Arc<CertifiedKey>,
    pub fingerprint: String,
    pub next_fingerprint: Option<String>,
    pub signer: Signer,
    pub verifiers: Vec<Verifier>,
}

impl Loaded {
    fn build(state: SkakelState) -> Result<Self, ServerError> {
        let (certified, fingerprint) = certified(&state.certificate)?;
        let next_fingerprint = match &state.next_certificate {
            Some(next) => Some(certified_fingerprint(&next.certificate)?),
            None => None,
        };
        let signer = Signer::load(&state.signing_key)?;
        let mut verifiers = vec![Verifier::load(&state.signing_key)?];
        for retired in &state.retired_signing_keys {
            verifiers.push(Verifier::load(retired)?);
        }
        Ok(Self {
            state,
            certified: Arc::new(certified),
            fingerprint,
            next_fingerprint,
            signer,
            verifiers,
        })
    }

    pub(crate) fn find(&self, client_id: &str) -> Option<&ClientRecord> {
        self.state.clients.iter().find(|c| c.id == client_id)
    }

    pub(crate) fn is_current(&self, client_id: &str, generation: u32) -> bool {
        self.find(client_id)
            .is_some_and(|client| client.generation == generation)
    }
}

fn der(text: &str) -> Result<Vec<u8>, ServerError> {
    STANDARD
        .decode(text)
        .map_err(|e| ServerError::State(format!("a saved certificate or key is not base64: {e}")))
}

fn certified(record: &CertificateRecord) -> Result<(CertifiedKey, String), ServerError> {
    let certificate = der(&record.certificate)?;
    let fingerprint = fingerprints::of_der(&certificate);
    let key = PrivatePkcs8KeyDer::from(der(&record.private_key)?);
    let signing = rustls::crypto::ring::sign::any_ecdsa_type(&PrivateKeyDer::Pkcs8(key))
        .map_err(|e| ServerError::State(format!("the saved certificate key is unusable: {e}")))?;
    Ok((
        CertifiedKey::new(vec![CertificateDer::from(certificate)], signing),
        fingerprint,
    ))
}

fn certified_fingerprint(record: &CertificateRecord) -> Result<String, ServerError> {
    Ok(fingerprints::of_der(&der(&record.certificate)?))
}

/// The server's state. One write at a time; readers see the last complete state.
pub(crate) struct ServerState {
    store: Arc<dyn SkakelStore>,
    keep_client_secrets: bool,
    certificate_host_name: String,
    organization: String,
    write: tokio::sync::Mutex<()>,
    current: watch::Sender<Arc<Loaded>>,
    last_seen: Mutex<HashMap<String, OffsetDateTime>>,
    raised: Mutex<(Vec<ClientView>, KeysView)>,
    pub(crate) events: Events,
}

impl ServerState {
    pub(crate) async fn start(
        store: Arc<dyn SkakelStore>,
        keep_client_secrets: bool,
        certificate_host_name: String,
        organization: String,
        events: Events,
    ) -> Result<Arc<Self>, ServerError> {
        let now = OffsetDateTime::now_utc();
        let state = match store.load().await.map_err(ServerError::Store)? {
            Some(mut state) => {
                if state
                    .retired_signing_keys
                    .iter()
                    .any(|r| r.accept_until.is_some_and(|until| until <= now))
                {
                    state.retired_signing_keys = unexpired(&state.retired_signing_keys, now);
                    store.save(&state).await.map_err(ServerError::Store)?;
                }
                state
            }
            None => {
                let state = SkakelState {
                    clients: vec![],
                    signing_key: crypto::create_signing_key(now)?,
                    retired_signing_keys: vec![],
                    certificate: crypto::create_certificate(
                        &certificate_host_name,
                        &organization,
                        now,
                    )?,
                    next_certificate: None,
                };
                store.save(&state).await.map_err(ServerError::Store)?;
                state
            }
        };
        let loaded = Arc::new(Loaded::build(state)?);
        let raised = (clients_of(&loaded, &HashMap::new()), keys_of(&loaded));
        Ok(Arc::new(Self {
            store,
            keep_client_secrets,
            certificate_host_name,
            organization,
            write: tokio::sync::Mutex::new(()),
            current: watch::Sender::new(loaded),
            last_seen: Mutex::new(HashMap::new()),
            raised: Mutex::new(raised),
            events,
        }))
    }

    pub(crate) fn loaded(&self) -> Arc<Loaded> {
        self.current.borrow().clone()
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<Arc<Loaded>> {
        self.current.subscribe()
    }

    pub(crate) fn fingerprint(&self) -> String {
        self.loaded().fingerprint.clone()
    }

    pub(crate) fn clients(&self) -> Vec<ClientView> {
        clients_of(&self.loaded(), &self.last_seen.lock().expect("lock"))
    }

    pub(crate) fn keys(&self) -> KeysView {
        keys_of(&self.loaded())
    }

    pub(crate) fn find(&self, client_id: &str) -> Option<ClientRecord> {
        self.loaded().find(client_id).cloned()
    }

    /// A token's principal, when its signature, issuer and lifetime hold and its client still
    /// exists at the generation it was issued for.
    pub(crate) fn authenticate(&self, token: &str) -> Option<Principal> {
        let loaded = self.loaded();
        let principal = crypto::read_token(&loaded.verifiers, token, OffsetDateTime::now_utc())?;
        loaded
            .is_current(&principal.client_id, principal.generation)
            .then_some(principal)
    }

    /// The client's generation when `secret` is its secret, and a note that it was seen.
    pub(crate) fn validate(&self, client_id: &str, secret: &str) -> Option<u32> {
        let loaded = self.loaded();
        let client = loaded.find(client_id)?;
        if !util::verify_secret(secret, &client.secret_hash) {
            return None;
        }
        self.last_seen
            .lock()
            .expect("lock")
            .insert(client_id.to_owned(), OffsetDateTime::now_utc());
        Some(client.generation)
    }

    pub(crate) fn issue_token(
        &self,
        client_id: &str,
        generation: u32,
    ) -> Result<(String, OffsetDateTime), ServerError> {
        let loaded = self.loaded();
        Ok(crypto::issue_token(
            &loaded.signer,
            client_id,
            generation,
            OffsetDateTime::now_utc(),
            ACCESS_TOKEN_LIFETIME,
        )?)
    }

    /// Applies `change` to the state, saves the result and makes it current. A change that
    /// returns `None` leaves everything as it was.
    pub(crate) async fn update(
        &self,
        change: impl FnOnce(&SkakelState) -> Option<SkakelState>,
    ) -> Result<(), ServerError> {
        {
            let _writing = self.write.lock().await;
            let previous = self.loaded();
            let Some(next) = change(&previous.state) else {
                return Ok(());
            };
            self.store.save(&next).await.map_err(ServerError::Store)?;
            let loaded = Arc::new(Loaded::build(next)?);
            self.current.send_replace(loaded);
        }
        self.raise_views();
        Ok(())
    }

    fn raise_views(&self) {
        let loaded = self.loaded();
        let clients = clients_of(&loaded, &self.last_seen.lock().expect("lock"));
        let keys = keys_of(&loaded);
        let (clients_changed, keys_changed) = {
            let mut raised = self.raised.lock().expect("lock");
            // `last_seen` alone is no reason to tell the app.
            let strip = |list: &[ClientView]| -> Vec<(String, String, bool)> {
                list.iter()
                    .map(|c| (c.id.clone(), c.name.clone(), c.has_next_certificate))
                    .collect()
            };
            let clients_changed = strip(&raised.0) != strip(&clients);
            let keys_changed = raised.1 != keys;
            *raised = (clients.clone(), keys.clone());
            (clients_changed, keys_changed)
        };
        if clients_changed {
            self.events.emit(ServerEvent::Clients(clients));
        }
        if keys_changed {
            self.events.emit(ServerEvent::Keys(keys));
        }
    }

    pub(crate) async fn register_client(&self, name: &str) -> Result<NewClient, ServerError> {
        let clean = util::clean_client_name(name);
        if clean.is_empty() {
            return Err(ServerError::Invalid(
                "The name is empty once control and format characters and the spaces around it are taken out.".into(),
            ));
        }
        let secret = util::new_secret();
        let client = ClientRecord {
            id: util::new_id("client"),
            name: clean,
            secret_hash: util::hash_secret(&secret),
            created_at: OffsetDateTime::now_utc(),
            generation: 1,
            secret: self.keep_client_secrets.then(|| secret.clone()),
        };
        let added = client.clone();
        self.update(move |state| {
            let mut next = state.clone();
            next.clients.push(added);
            Some(next)
        })
        .await?;
        Ok(NewClient {
            client_id: client.id,
            name: client.name,
            client_secret: secret,
        })
    }

    pub(crate) async fn rotate_secret(&self, client_id: &str) -> Result<Option<String>, ServerError> {
        let secret = util::new_secret();
        let keep = self.keep_client_secrets;
        let hash = util::hash_secret(&secret);
        let mut found = false;
        self.update(|state| {
            let mut next = state.clone();
            let client = next.clients.iter_mut().find(|c| c.id == client_id)?;
            client.secret_hash = hash;
            client.secret = keep.then(|| secret.clone());
            client.generation += 1;
            found = true;
            Some(next)
        })
        .await?;
        Ok(found.then_some(secret))
    }

    pub(crate) async fn revoke_client(&self, client_id: &str) -> Result<bool, ServerError> {
        let mut found = false;
        self.update(|state| {
            let mut next = state.clone();
            let before = next.clients.len();
            next.clients.retain(|c| c.id != client_id);
            if next.clients.len() == before {
                return None;
            }
            if let Some(next_certificate) = &mut next.next_certificate {
                next_certificate.received_by.retain(|id| id != client_id);
            }
            found = true;
            Some(next)
        })
        .await?;
        self.last_seen.lock().expect("lock").remove(client_id);
        Ok(found)
    }

    pub(crate) async fn rotate_signing_key(&self) -> Result<String, ServerError> {
        let now = OffsetDateTime::now_utc();
        let key = crypto::create_signing_key(now)?;
        let id = key.key_id.clone();
        self.update(move |state| {
            let mut next = state.clone();
            let mut retired = unexpired(&state.retired_signing_keys, now);
            let mut old = state.signing_key.clone();
            old.accept_until = Some(now + ACCESS_TOKEN_LIFETIME + RETIRED_KEY_MARGIN);
            retired.push(old);
            next.signing_key = key;
            next.retired_signing_keys = retired;
            Some(next)
        })
        .await?;
        Ok(id)
    }

    /// Drops the replaced signing keys whose time is up.
    pub(crate) async fn prune_retired_keys(&self) -> Result<(), ServerError> {
        let now = OffsetDateTime::now_utc();
        self.update(|state| {
            state
                .retired_signing_keys
                .iter()
                .any(|r| r.accept_until.is_some_and(|until| until <= now))
                .then(|| SkakelState {
                    retired_signing_keys: unexpired(&state.retired_signing_keys, now),
                    ..state.clone()
                })
        })
        .await
    }

    pub(crate) async fn prepare_certificate(&self) -> Result<Option<String>, ServerError> {
        if self.loaded().state.next_certificate.is_some() {
            return Ok(None);
        }
        let now = OffsetDateTime::now_utc();
        let certificate =
            crypto::create_certificate(&self.certificate_host_name, &self.organization, now)?;
        let wanted = certificate.certificate.clone();
        self.update(move |state| {
            state.next_certificate.is_none().then(|| SkakelState {
                next_certificate: Some(NextCertificateRecord {
                    certificate,
                    prepared_at: now,
                    received_by: vec![],
                }),
                ..state.clone()
            })
        })
        .await?;
        let loaded = self.loaded();
        Ok(loaded
            .state
            .next_certificate
            .as_ref()
            .filter(|next| next.certificate.certificate == wanted)
            .and(loaded.next_fingerprint.clone()))
    }

    pub(crate) async fn cancel_certificate(&self) -> Result<bool, ServerError> {
        let mut dropped = false;
        self.update(|state| {
            dropped = state.next_certificate.is_some();
            dropped.then(|| SkakelState {
                next_certificate: None,
                ..state.clone()
            })
        })
        .await?;
        Ok(dropped)
    }

    pub(crate) async fn switch_certificate(&self) -> Result<Option<CertificateSwitch>, ServerError> {
        let from = self.fingerprint();
        let mut switched: Option<(NextCertificateRecord, Vec<ClientRecord>)> = None;
        self.update(|state| {
            let next = state.next_certificate.clone()?;
            switched = Some((next.clone(), state.clients.clone()));
            Some(SkakelState {
                certificate: next.certificate,
                next_certificate: None,
                ..state.clone()
            })
        })
        .await?;
        Ok(switched.map(|(next, clients)| CertificateSwitch {
            from,
            to: self.fingerprint(),
            not_received: clients
                .iter()
                .filter(|c| !next.received_by.contains(&c.id))
                .map(|c| c.name.clone())
                .collect(),
        }))
    }

    pub(crate) async fn mark_next_certificate_received(
        &self,
        client_id: &str,
        fingerprint: &str,
    ) -> Result<(), ServerError> {
        let loaded = self.loaded();
        let Some(next) = &loaded.state.next_certificate else {
            return Ok(());
        };
        let matches = loaded
            .next_fingerprint
            .as_deref()
            .is_some_and(|expected| fingerprints::are_equal(fingerprint, expected));
        if next.received_by.iter().any(|id| id == client_id)
            || loaded.find(client_id).is_none()
            || !matches
        {
            return Ok(());
        }
        let certificate = next.certificate.certificate.clone();
        self.update(|state| {
            let mut next = state.clone();
            let n = next.next_certificate.as_mut()?;
            if n.certificate.certificate != certificate
                || n.received_by.iter().any(|id| id == client_id)
                || !state.clients.iter().any(|c| c.id == client_id)
            {
                return None;
            }
            n.received_by.push(client_id.to_owned());
            Some(next)
        })
        .await
    }
}

fn unexpired(retired: &[KeyRecord], now: OffsetDateTime) -> Vec<KeyRecord> {
    retired
        .iter()
        .filter(|r| r.accept_until.is_none_or(|until| until > now))
        .cloned()
        .collect()
}

fn clients_of(loaded: &Loaded, seen: &HashMap<String, OffsetDateTime>) -> Vec<ClientView> {
    loaded
        .state
        .clients
        .iter()
        .map(|c| ClientView {
            id: c.id.clone(),
            name: c.name.clone(),
            created_at: c.created_at,
            last_seen: seen.get(&c.id).copied(),
            has_next_certificate: loaded
                .state
                .next_certificate
                .as_ref()
                .is_some_and(|n| n.received_by.contains(&c.id)),
            has_secret: c.secret.is_some(),
        })
        .collect()
}

fn keys_of(loaded: &Loaded) -> KeysView {
    let state = &loaded.state;
    KeysView {
        fingerprint: loaded.fingerprint.clone(),
        next_fingerprint: loaded.next_fingerprint.clone(),
        next_prepared_at: state.next_certificate.as_ref().map(|n| n.prepared_at),
        signing_key_id: state.signing_key.key_id.clone(),
        signing_key_since: state.signing_key.created_at,
        retired_keys_until: state
            .retired_signing_keys
            .iter()
            .filter_map(|r| r.accept_until)
            .max(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::InMemoryStore;

    async fn state_with(store: Arc<InMemoryStore>) -> Arc<ServerState> {
        ServerState::start(store, false, "pi-lab".into(), "test-app".into(), Events::new(vec![]))
            .await
            .unwrap()
    }

    async fn state() -> Arc<ServerState> {
        state_with(Arc::new(InMemoryStore::new())).await
    }

    #[tokio::test]
    async fn the_first_start_makes_keys_and_saves_them() {
        let store = Arc::new(InMemoryStore::new());

        let state = state_with(store.clone()).await;

        let saved = store.state().unwrap();
        assert!(saved.clients.is_empty());
        assert_eq!(
            fingerprints::of_der(&der(&saved.certificate.certificate).unwrap()),
            state.fingerprint()
        );
    }

    #[tokio::test]
    async fn a_second_start_on_the_same_store_has_the_same_certificate_and_clients() {
        let store = Arc::new(InMemoryStore::new());
        let first = state_with(store.clone()).await;
        let client = first.register_client("lab pc").await.unwrap();

        let second = state_with(store).await;

        assert_eq!(second.fingerprint(), first.fingerprint());
        assert_eq!(second.find(&client.client_id).unwrap().name, "lab pc");
    }

    #[tokio::test]
    async fn a_registered_client_proves_itself_with_its_secret_and_is_named_clean() {
        let state = state().await;

        let client = state.register_client("  lab\u{202E} pc ").await.unwrap();

        assert_eq!(client.name, "lab pc");
        assert_eq!(state.validate(&client.client_id, &client.client_secret), Some(1));
        assert_eq!(state.validate(&client.client_id, "wrong"), None);
        assert_eq!(state.validate("client-none", &client.client_secret), None);
        assert!(state.register_client("\u{0}").await.is_err());
    }

    #[tokio::test]
    async fn rotating_a_secret_raises_the_generation_and_stales_the_old_token() {
        let state = state().await;
        let client = state.register_client("lab pc").await.unwrap();
        let (token, _) = state.issue_token(&client.client_id, 1).unwrap();
        assert!(state.authenticate(&token).is_some());

        let secret = state.rotate_secret(&client.client_id).await.unwrap().unwrap();

        assert_eq!(state.validate(&client.client_id, &client.client_secret), None);
        assert_eq!(state.validate(&client.client_id, &secret), Some(2));
        assert!(state.authenticate(&token).is_none());
        assert_eq!(state.rotate_secret("client-none").await.unwrap(), None);
    }

    #[tokio::test]
    async fn revoking_a_client_refuses_its_tokens_at_once_and_only_once() {
        let state = state().await;
        let client = state.register_client("lab pc").await.unwrap();
        let (token, _) = state.issue_token(&client.client_id, 1).unwrap();

        assert!(state.revoke_client(&client.client_id).await.unwrap());

        assert!(state.authenticate(&token).is_none());
        assert!(state.find(&client.client_id).is_none());
        assert!(!state.revoke_client(&client.client_id).await.unwrap());
    }

    #[tokio::test]
    async fn a_rotated_signing_key_still_takes_the_old_tokens() {
        let state = state().await;
        let client = state.register_client("lab pc").await.unwrap();
        let (token, _) = state.issue_token(&client.client_id, 1).unwrap();
        let before = state.keys().signing_key_id;

        let after = state.rotate_signing_key().await.unwrap();

        assert_ne!(before, after);
        assert!(state.authenticate(&token).is_some());
        assert!(state.keys().retired_keys_until.is_some());
    }

    #[tokio::test]
    async fn a_handover_prepares_waits_for_acknowledgements_and_switches() {
        let state = state().await;
        let a = state.register_client("a").await.unwrap();
        state.register_client("b").await.unwrap();
        let current = state.fingerprint();

        let next = state.prepare_certificate().await.unwrap().unwrap();
        assert_eq!(state.prepare_certificate().await.unwrap(), None);
        state
            .mark_next_certificate_received(&a.client_id, "not the one")
            .await
            .unwrap();
        assert!(!state.clients()[0].has_next_certificate);
        state
            .mark_next_certificate_received(&a.client_id, &next)
            .await
            .unwrap();
        assert!(state.clients()[0].has_next_certificate);
        let switched = state.switch_certificate().await.unwrap().unwrap();

        assert_eq!(switched.from, current);
        assert_eq!(switched.to, next);
        assert_eq!(switched.not_received, ["b"]);
        assert_eq!(state.fingerprint(), next);
        assert_eq!(state.keys().next_fingerprint, None);
        assert!(state.switch_certificate().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_cancelled_handover_leaves_the_certificate_alone() {
        let state = state().await;
        let current = state.fingerprint();
        state.prepare_certificate().await.unwrap();

        assert!(state.cancel_certificate().await.unwrap());

        assert_eq!(state.fingerprint(), current);
        assert_eq!(state.keys().next_fingerprint, None);
        assert!(!state.cancel_certificate().await.unwrap());
    }

    #[tokio::test]
    async fn a_change_that_cannot_be_saved_is_not_made() {
        struct Failing;
        impl SkakelStore for Failing {
            fn load(&self) -> crate::store::StoreFuture<'_, Option<SkakelState>> {
                Box::pin(async { Ok(None) })
            }
            fn save<'a>(&'a self, state: &'a SkakelState) -> crate::store::StoreFuture<'a, ()> {
                let first = state.clients.is_empty();
                Box::pin(async move {
                    if first {
                        Ok(())
                    } else {
                        Err(std::io::Error::other("disk full"))
                    }
                })
            }
        }
        let state = ServerState::start(
            Arc::new(Failing),
            false,
            "pi-lab".into(),
            "test-app".into(),
            Events::new(vec![]),
        )
        .await
        .unwrap();

        assert!(state.register_client("lab pc").await.is_err());
        assert!(state.clients().is_empty());
    }

    #[tokio::test]
    async fn changes_are_told_to_the_app() {
        let store = Arc::new(InMemoryStore::new());
        let events = Events::new(vec![]);
        let mut listener = events.subscribe();
        let state = ServerState::start(store, false, "pi-lab".into(), "t".into(), events)
            .await
            .unwrap();

        state.register_client("lab pc").await.unwrap();
        state.rotate_signing_key().await.unwrap();

        assert!(matches!(listener.try_recv(), Ok(ServerEvent::Clients(c)) if c.len() == 1));
        assert!(matches!(listener.try_recv(), Ok(ServerEvent::Keys(_))));
        assert!(listener.try_recv().is_err());
    }
}
