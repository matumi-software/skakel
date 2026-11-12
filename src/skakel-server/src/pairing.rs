//! Pairing: requests a client opens, the person's approval and the credentials that follow.
//!
//! A request is opened with a commitment, revealed with the client's nonce, and then waits for a
//! person to type the six-digit code both ends worked out. The app shows the waiting requests
//! (see [`PairingOverview`]) and calls [`Pairing::approve`] or [`Pairing::deny`].

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use skakel_pairing::{
    PAIR_APPROVED, PAIR_DENIED, PAIR_EXPIRED, PAIR_WAITING, PairOpened, PairPoll, PairState,
    compute, is_code, matches, new_nonce,
};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::error::ServerError;
use crate::events::ServerEvent;
use crate::state::ServerState;
use crate::util;

/// How long a request lives.
pub(crate) const LIFETIME: Duration = Duration::from_secs(5 * 60);
/// How long a request may wait before it reveals.
pub(crate) const UNREVEALED_LIFETIME: Duration = Duration::from_secs(30);
/// How long a refused request stays on the app's list.
const DENIED_VISIBLE_FOR: Duration = Duration::from_secs(15);
/// How often the server looks for requests that ran out.
const SWEEP_INTERVAL: Duration = Duration::from_secs(5);
/// The window the open and reveal budgets count over.
const OPEN_WINDOW: Duration = Duration::from_secs(5 * 60);
/// Revealed requests the whole server takes per window.
pub(crate) const REVEALS_PER_WINDOW: usize = 60;
/// Opens one address makes per window.
pub(crate) const OPENS_PER_ADDRESS_PER_WINDOW: usize = 5;
/// Revealed requests waiting for a person at once.
pub(crate) const MAX_OPEN: usize = 10;
/// Open requests one address may have at once.
pub(crate) const MAX_OPEN_PER_ADDRESS: usize = 3;
/// Wrong codes that refuse a request.
pub(crate) const MAX_WRONG_CODES: u32 = 3;
/// Requests that have opened and not yet revealed, for the whole server.
pub(crate) const MAX_UNREVEALED: usize = 64;
/// The fewest characters a revealed nonce may have: a client's own is 32 bytes as base64url, 43.
pub(crate) const MIN_NONCE_LENGTH: usize = 43;

/// A request waiting for a person, or lately refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PairingRequest {
    /// The id the app passes to [`Pairing::approve`].
    pub id: String,
    /// The name the client gave itself, cleaned.
    pub client_name: String,
    /// The address it came from.
    pub from: String,
    /// When it arrived.
    pub requested_at: OffsetDateTime,
    /// When it runs out.
    pub expires_at: OffsetDateTime,
    /// `waiting` or `denied`.
    pub state: String,
    /// For a refused request, why.
    pub message: Option<String>,
}

/// The requests a person can see, and whether the server takes any more for now.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PairingOverview {
    /// Revealed requests waiting, and refused ones for a few seconds, newest first.
    pub requests: Vec<PairingRequest>,
    /// True when the server's budget of revealed requests is spent.
    pub budget_exhausted: bool,
}

/// What came of typing a code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Approval {
    /// There is no such request, or it is no longer waiting.
    NotWaiting,
    /// The code was wrong.
    WrongCode,
    /// The code was right and the client is registered.
    Approved,
}

/// How a request ended, for the app's log.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PairingDecision {
    /// The request.
    pub request_id: String,
    /// The client's name.
    pub client_name: String,
    /// The address it came from.
    pub from: String,
    /// The new client's id when it was approved.
    pub client_id: Option<String>,
    /// Why it was refused, otherwise.
    pub refusal: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reveal {
    Revealed,
    NotFound,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Waiting,
    Approved,
    Denied,
    Expired,
    /// The right code was typed and the client is being saved; to everyone else still waiting.
    Registering,
}

impl Stage {
    fn text(self) -> &'static str {
        match self {
            Self::Waiting | Self::Registering => PAIR_WAITING,
            Self::Approved => PAIR_APPROVED,
            Self::Denied => PAIR_DENIED,
            Self::Expired => PAIR_EXPIRED,
        }
    }
}

struct Request {
    id: String,
    client_name: String,
    from: String,
    address_key: String,
    commitment: String,
    server_nonce: String,
    poll_token: String,
    requested: Instant,
    expires: Instant,
    requested_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    code: Option<String>,
    stage: Stage,
    wrong_codes: u32,
    message: Option<String>,
    show_until: Option<Instant>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

impl Request {
    fn is_stale(&self, now: Instant) -> bool {
        self.stage == Stage::Waiting
            && self.code.is_none()
            && self.requested + UNREVEALED_LIFETIME <= now
    }

    fn is_live(&self, now: Instant) -> bool {
        self.stage == Stage::Waiting && self.expires > now && !self.is_stale(now)
    }

    fn is_revealed_and_waiting(&self, now: Instant) -> bool {
        self.stage == Stage::Waiting && self.code.is_some() && self.expires > now
    }

    fn is_visible(&self, now: Instant) -> bool {
        self.is_revealed_and_waiting(now)
            || (self.stage == Stage::Denied && self.show_until.is_some_and(|until| until > now))
    }

    /// Marks a waiting request that ran out as expired; true when a person could see it.
    fn lapse(&mut self, now: Instant) -> bool {
        if self.stage != Stage::Waiting || self.expires > now {
            return false;
        }
        self.stage = Stage::Expired;
        self.code.is_some()
    }
}

#[derive(Default)]
struct Data {
    requests: HashMap<String, Request>,
    opens: VecDeque<(Instant, String)>,
    reveals: VecDeque<Instant>,
    opens_by_address: HashMap<String, usize>,
    pushed: String,
}

impl Data {
    fn forget_old_opens(&mut self, now: Instant) {
        while self
            .reveals
            .front()
            .is_some_and(|at| *at + OPEN_WINDOW <= now)
        {
            self.reveals.pop_front();
        }
        while self
            .opens
            .front()
            .is_some_and(|(at, _)| *at + OPEN_WINDOW <= now)
        {
            let (_, key) = self.opens.pop_front().expect("front was Some");
            match self.opens_by_address.get_mut(&key) {
                Some(count) if *count > 1 => *count -= 1,
                _ => {
                    self.opens_by_address.remove(&key);
                }
            }
        }
    }

    fn revealed_and_waiting(&self, now: Instant) -> usize {
        self.requests
            .values()
            .filter(|r| r.is_revealed_and_waiting(now))
            .count()
    }

    fn unrevealed(&self, now: Instant) -> usize {
        self.requests
            .values()
            .filter(|r| r.stage == Stage::Waiting && r.code.is_none() && r.is_live(now))
            .count()
    }

    fn overview(&mut self, now: Instant) -> PairingOverview {
        self.forget_old_opens(now);
        let mut requests: Vec<&Request> = self
            .requests
            .values()
            .filter(|r| r.is_visible(now))
            .collect();
        requests.sort_by_key(|r| std::cmp::Reverse(r.requested));
        PairingOverview {
            requests: requests
                .into_iter()
                .map(|r| PairingRequest {
                    id: r.id.clone(),
                    client_name: r.client_name.clone(),
                    from: r.from.clone(),
                    requested_at: r.requested_at,
                    expires_at: r.expires_at,
                    state: r.stage.text().to_owned(),
                    message: (r.stage == Stage::Denied)
                        .then(|| r.message.clone())
                        .flatten(),
                })
                .collect(),
            budget_exhausted: self.reveals.len() >= REVEALS_PER_WINDOW,
        }
    }
}

fn signature(overview: &PairingOverview) -> String {
    let ids: Vec<String> = overview
        .requests
        .iter()
        .map(|r| format!("{}:{}", r.id, r.state))
        .collect();
    format!("{}|{}", overview.budget_exhausted, ids.join("|"))
}

/// The pairing requests of a server. Cloning gives another handle to the same requests.
#[derive(Clone)]
pub struct Pairing {
    inner: Arc<Inner>,
}

struct Inner {
    state: Arc<ServerState>,
    data: Mutex<Data>,
}

impl Pairing {
    pub(crate) fn new(state: Arc<ServerState>) -> Self {
        Self {
            inner: Arc::new(Inner {
                state,
                data: Mutex::new(Data::default()),
            }),
        }
    }

    /// Looks for requests that ran out every few seconds until the server is dropped.
    pub(crate) fn spawn_sweeper(&self) {
        let weak = Arc::downgrade(&self.inner);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(SWEEP_INTERVAL);
            tick.tick().await;
            loop {
                tick.tick().await;
                let Some(inner) = weak.upgrade() else { return };
                Pairing { inner }.sweep().await;
            }
        });
    }

    /// The requests a person can see now.
    pub async fn overview(&self) -> PairingOverview {
        self.inner.data.lock().await.overview(Instant::now())
    }

    /// Types a code for a request. A right code registers the client; a third wrong one refuses
    /// the request.
    pub async fn approve(
        &self,
        request_id: &str,
        typed_code: &str,
    ) -> Result<Approval, ServerError> {
        let mut decision = None;
        let result;
        let changed;
        let mut register_for = None;
        {
            let mut data = self.inner.data.lock().await;
            let now = Instant::now();
            let Some(request) = data.requests.get_mut(request_id) else {
                return Ok(Approval::NotWaiting);
            };
            let mut touched = request.lapse(now);
            match request.code.clone() {
                Some(code) if request.stage == Stage::Waiting => {
                    if is_code(&code, typed_code) {
                        // Saving the client waits on the store, so the lock is let go first. The
                        // request is marked so a second right code cannot register it again.
                        request.stage = Stage::Registering;
                        register_for = Some(request.client_name.clone());
                        result = Approval::Approved;
                    } else {
                        result = Approval::WrongCode;
                        request.wrong_codes += 1;
                        if request.wrong_codes >= MAX_WRONG_CODES {
                            let message = "The code was wrong three times.".to_owned();
                            request.stage = Stage::Denied;
                            request.message = Some(message.clone());
                            request.show_until = Some(now + DENIED_VISIBLE_FOR);
                            touched = true;
                            decision = Some(PairingDecision {
                                request_id: request.id.clone(),
                                client_name: request.client_name.clone(),
                                from: request.from.clone(),
                                client_id: None,
                                refusal: Some(message),
                            });
                        }
                    }
                }
                _ => result = Approval::NotWaiting,
            }
            changed = touched;
        }
        if let Some(name) = register_for {
            let registered = self.inner.state.register_client(&name).await;
            let mut data = self.inner.data.lock().await;
            let Some(request) = data.requests.get_mut(request_id) else {
                // Swept while it was being saved; the client stays registered, as it was typed.
                return registered.map(|_| result);
            };
            match registered {
                Ok(client) => {
                    request.client_id = Some(client.client_id.clone());
                    request.client_secret = Some(client.client_secret);
                    request.stage = Stage::Approved;
                    decision = Some(PairingDecision {
                        request_id: request.id.clone(),
                        client_name: request.client_name.clone(),
                        from: request.from.clone(),
                        client_id: Some(client.client_id),
                        refusal: None,
                    });
                }
                Err(error) => {
                    request.stage = Stage::Waiting;
                    return Err(error);
                }
            }
            drop(data);
            self.raise().await;
        } else if changed {
            self.raise().await;
        }
        if let Some(decision) = decision {
            self.inner.state.events.emit(ServerEvent::Decided(decision));
        }
        Ok(result)
    }

    /// Refuses a request on the server. False when it is not waiting for a person.
    pub async fn deny(&self, request_id: &str) -> bool {
        let decision;
        {
            let mut data = self.inner.data.lock().await;
            let now = Instant::now();
            let Some(request) = data.requests.get_mut(request_id) else {
                return false;
            };
            request.lapse(now);
            if request.stage != Stage::Waiting || request.code.is_none() {
                return false;
            }
            request.stage = Stage::Denied;
            request.message = Some("Refused on the server.".to_owned());
            request.show_until = Some(now + DENIED_VISIBLE_FOR);
            decision = PairingDecision {
                request_id: request.id.clone(),
                client_name: request.client_name.clone(),
                from: request.from.clone(),
                client_id: None,
                refusal: Some("Refused on the server.".to_owned()),
            };
        }
        self.raise().await;
        self.inner.state.events.emit(ServerEvent::Decided(decision));
        true
    }

    /// Opens a request. `None` when this server takes no more from this address for now.
    pub(crate) async fn open(
        &self,
        client_name: &str,
        commitment: &str,
        from: IpAddr,
    ) -> Option<PairOpened> {
        let server_nonce = match new_nonce() {
            Ok(nonce) => nonce,
            Err(error) => {
                // Nothing safe to open a request with; the caller answers as for a full server.
                log::error!("A pairing request was refused: {error}");
                return None;
            }
        };
        let now = Instant::now();
        let key = util::address_key(from);
        let mut data = self.inner.data.lock().await;
        data.forget_old_opens(now);
        if data.reveals.len() >= REVEALS_PER_WINDOW
            || data.opens_by_address.get(&key).copied().unwrap_or(0) >= OPENS_PER_ADDRESS_PER_WINDOW
            || data.revealed_and_waiting(now) >= MAX_OPEN
            || data.unrevealed(now) >= MAX_UNREVEALED
            || data
                .requests
                .values()
                .filter(|r| r.address_key == key && r.is_live(now))
                .count()
                >= MAX_OPEN_PER_ADDRESS
        {
            return None;
        }
        data.opens.push_back((now, key.clone()));
        *data.opens_by_address.entry(key.clone()).or_insert(0) += 1;

        let wall = OffsetDateTime::now_utc();
        let request = Request {
            id: util::hex_upper(&util::random::<16>()),
            client_name: client_name.to_owned(),
            from: util::address_text(from),
            address_key: key,
            commitment: commitment.to_owned(),
            server_nonce,
            poll_token: util::new_token(),
            requested: now,
            expires: now + LIFETIME,
            requested_at: wall,
            expires_at: wall + LIFETIME,
            code: None,
            stage: Stage::Waiting,
            wrong_codes: 0,
            message: None,
            show_until: None,
            client_id: None,
            client_secret: None,
        };
        let opened = PairOpened {
            request_id: request.id.clone(),
            server_nonce: request.server_nonce.clone(),
            expires_at: request.expires_at,
            poll_token: request.poll_token.clone(),
        };
        data.requests.insert(request.id.clone(), request);
        Some(opened)
    }

    /// Takes the client's nonce, checks it against the commitment and works out the code.
    pub(crate) async fn reveal(&self, request_id: &str, client_nonce: &str) -> Reveal {
        let result;
        {
            let mut data = self.inner.data.lock().await;
            let now = Instant::now();
            let Some(request) = data.requests.get(request_id) else {
                return Reveal::NotFound;
            };
            if request.stage != Stage::Waiting
                || request.code.is_some()
                || request.is_stale(now)
                || request.expires <= now
                || client_nonce.len() < MIN_NONCE_LENGTH
                || !matches(&request.commitment, client_nonce)
            {
                return Reveal::NotFound;
            }
            let Some(code) = compute(
                &self.inner.state.fingerprint(),
                client_nonce,
                &request.server_nonce,
            ) else {
                // The server's own certificate has no usable fingerprint, so no code can be made.
                log::error!(
                    "The server's fingerprint is not 64 hex digits, so no pairing code can be made."
                );
                return Reveal::NotFound;
            };
            data.forget_old_opens(now);
            if data.reveals.len() >= REVEALS_PER_WINDOW
                || data.revealed_and_waiting(now) >= MAX_OPEN
            {
                result = Reveal::Full;
            } else {
                data.reveals.push_back(now);
                data.requests
                    .get_mut(request_id)
                    .expect("looked up above")
                    .code = Some(code);
                result = Reveal::Revealed;
            }
        }
        if result == Reveal::Revealed {
            self.raise().await;
        }
        result
    }

    /// The state of a request, with the credentials once, when it was approved. `None` for an
    /// unknown request or a wrong token.
    pub(crate) async fn poll(
        &self,
        request_id: &str,
        poll_token: Option<&str>,
    ) -> Option<PairPoll> {
        let poll;
        let changed;
        {
            let mut data = self.inner.data.lock().await;
            let now = Instant::now();
            let request = data.requests.get_mut(request_id)?;
            if !util::same_token(&request.poll_token, poll_token) {
                return None;
            }
            changed = request.lapse(now);
            if request.stage == Stage::Approved {
                let credentials = PairPoll {
                    state: PairState::Approved,
                    client_id: request.client_id.clone(),
                    client_secret: request.client_secret.take(),
                };
                data.requests.remove(request_id);
                poll = Some(credentials);
            } else {
                poll = Some(PairPoll::state(request.stage.text()));
            }
        }
        if changed {
            self.raise().await;
        }
        poll
    }

    /// Withdraws a waiting request. False for an unknown request, a wrong token, or one that is
    /// no longer waiting.
    pub(crate) async fn withdraw(&self, request_id: &str, poll_token: Option<&str>) -> bool {
        let was_visible;
        {
            let mut data = self.inner.data.lock().await;
            let now = Instant::now();
            let Some(request) = data.requests.get_mut(request_id) else {
                return false;
            };
            if !util::same_token(&request.poll_token, poll_token) {
                return false;
            }
            request.lapse(now);
            if request.stage != Stage::Waiting {
                return false;
            }
            was_visible = request.code.is_some();
            data.requests.remove(request_id);
        }
        if was_visible {
            self.raise().await;
        }
        true
    }

    /// Marks what ran out and forgets what is long over, and tells the app when the list changed.
    pub(crate) async fn sweep(&self) {
        let overview;
        {
            let mut data = self.inner.data.lock().await;
            let now = Instant::now();
            for request in data.requests.values_mut() {
                request.lapse(now);
            }
            data.requests
                .retain(|_, r| !(r.is_stale(now) || r.expires + LIFETIME <= now));
            overview = data.overview(now);
            if signature(&overview) == data.pushed {
                return;
            }
            data.pushed = signature(&overview);
        }
        self.inner.state.events.emit(ServerEvent::Pairing(overview));
    }

    async fn raise(&self) {
        let overview = {
            let mut data = self.inner.data.lock().await;
            let overview = data.overview(Instant::now());
            data.pushed = signature(&overview);
            overview
        };
        self.inner.state.events.emit(ServerEvent::Pairing(overview));
    }
}

/// The nonce the client commits to, for tests of the whole exchange.
#[cfg(test)]
pub(crate) fn commitment_of(nonce: &str) -> String {
    skakel_pairing::commit(nonce)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::events::Events;
    use crate::store::InMemoryStore;

    fn addr(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    async fn pairing() -> (Pairing, Arc<ServerState>) {
        let state = ServerState::start(
            Arc::new(InMemoryStore::new()),
            false,
            "pi-lab".into(),
            "test-app".into(),
            Events::new(vec![]),
        )
        .await
        .unwrap();
        (Pairing::new(state.clone()), state)
    }

    /// Opens and reveals a request, as a client does; returns the opened request, the nonce and
    /// the code both ends have.
    async fn revealed(
        pairing: &Pairing,
        state: &ServerState,
        from: IpAddr,
    ) -> (PairOpened, String) {
        let nonce = new_nonce().unwrap();
        let opened = pairing
            .open("lab pc", &commitment_of(&nonce), from)
            .await
            .expect("opened");
        assert_eq!(
            pairing.reveal(&opened.request_id, &nonce).await,
            Reveal::Revealed
        );
        let code = compute(&state.fingerprint(), &nonce, &opened.server_nonce).unwrap();
        (opened, code)
    }

    #[tokio::test(start_paused = true)]
    async fn a_right_code_registers_the_client_and_the_poll_hands_over_its_credentials_once() {
        let (pairing, state) = pairing().await;
        let (opened, code) = revealed(&pairing, &state, addr(1)).await;
        let token = Some(opened.poll_token.as_str());
        assert_eq!(
            pairing.poll(&opened.request_id, token).await.unwrap().state,
            PairState::Waiting
        );
        assert_eq!(pairing.overview().await.requests.len(), 1);

        assert_eq!(
            pairing.approve(&opened.request_id, &code).await.unwrap(),
            Approval::Approved
        );

        let poll = pairing.poll(&opened.request_id, token).await.unwrap();
        assert_eq!(poll.state, PairState::Approved);
        let (id, secret) = (poll.client_id.unwrap(), poll.client_secret.unwrap());
        assert_eq!(state.validate(&id, &secret), Some(1));
        assert_eq!(state.find(&id).unwrap().name, "lab pc");
        assert!(pairing.poll(&opened.request_id, token).await.is_none());
        assert!(pairing.overview().await.requests.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_code_typed_with_spaces_is_taken_and_a_wrong_one_is_not() {
        let (pairing, state) = pairing().await;
        let (opened, code) = revealed(&pairing, &state, addr(1)).await;

        assert_eq!(
            pairing.approve(&opened.request_id, "000000").await.unwrap(),
            Approval::WrongCode
        );
        let spaced = format!("{} {}", &code[..3], &code[3..]);
        assert_eq!(
            pairing.approve(&opened.request_id, &spaced).await.unwrap(),
            Approval::Approved
        );
    }

    #[tokio::test(start_paused = true)]
    async fn three_wrong_codes_refuse_the_request_and_it_stays_on_the_list_for_a_moment() {
        let (pairing, state) = pairing().await;
        let (opened, code) = revealed(&pairing, &state, addr(1)).await;
        let wrong = if code == "000000" { "111111" } else { "000000" };

        for _ in 0..3 {
            pairing.approve(&opened.request_id, wrong).await.unwrap();
        }

        let overview = pairing.overview().await;
        assert_eq!(overview.requests[0].state, "denied");
        assert_eq!(
            overview.requests[0].message.as_deref(),
            Some("The code was wrong three times.")
        );
        assert_eq!(
            pairing.approve(&opened.request_id, &code).await.unwrap(),
            Approval::NotWaiting
        );
        let token = Some(opened.poll_token.as_str());
        assert_eq!(
            pairing.poll(&opened.request_id, token).await.unwrap().state,
            PairState::Denied
        );
        tokio::time::advance(Duration::from_secs(16)).await;
        assert!(pairing.overview().await.requests.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn denying_refuses_a_waiting_request() {
        let (pairing, state) = pairing().await;
        let (opened, _) = revealed(&pairing, &state, addr(1)).await;

        assert!(pairing.deny(&opened.request_id).await);

        let token = Some(opened.poll_token.as_str());
        assert_eq!(
            pairing.poll(&opened.request_id, token).await.unwrap().state,
            PairState::Denied
        );
        assert!(!pairing.deny(&opened.request_id).await);
        assert!(!pairing.deny("nobody").await);
    }

    #[tokio::test(start_paused = true)]
    async fn a_reveal_with_the_wrong_nonce_or_twice_finds_nothing() {
        let (pairing, state) = pairing().await;
        let nonce = new_nonce().unwrap();
        let opened = pairing
            .open("lab pc", &commitment_of(&nonce), addr(1))
            .await
            .unwrap();

        assert_eq!(
            pairing.reveal(&opened.request_id, "other").await,
            Reveal::NotFound
        );
        assert_eq!(
            pairing.reveal(&opened.request_id, &nonce).await,
            Reveal::Revealed
        );
        assert_eq!(
            pairing.reveal(&opened.request_id, &nonce).await,
            Reveal::NotFound
        );
        assert_eq!(pairing.reveal("nobody", &nonce).await, Reveal::NotFound);
        let _ = state;
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_that_never_reveals_is_dropped_after_thirty_seconds() {
        let (pairing, _) = pairing().await;
        let nonce = new_nonce().unwrap();
        let opened = pairing
            .open("lab pc", &commitment_of(&nonce), addr(1))
            .await
            .unwrap();

        tokio::time::advance(Duration::from_secs(31)).await;

        assert_eq!(
            pairing.reveal(&opened.request_id, &nonce).await,
            Reveal::NotFound
        );
        pairing.sweep().await;
        let token = Some(opened.poll_token.as_str());
        assert!(pairing.poll(&opened.request_id, token).await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_expires_after_five_minutes() {
        let (pairing, state) = pairing().await;
        let (opened, code) = revealed(&pairing, &state, addr(1)).await;

        tokio::time::advance(Duration::from_secs(301)).await;

        let token = Some(opened.poll_token.as_str());
        assert_eq!(
            pairing.poll(&opened.request_id, token).await.unwrap().state,
            PairState::Expired
        );
        assert_eq!(
            pairing.approve(&opened.request_id, &code).await.unwrap(),
            Approval::NotWaiting
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_poll_and_the_withdrawal_need_the_poll_token() {
        let (pairing, state) = pairing().await;
        let (opened, _) = revealed(&pairing, &state, addr(1)).await;

        assert!(pairing.poll(&opened.request_id, None).await.is_none());
        assert!(
            pairing
                .poll(&opened.request_id, Some("wrong"))
                .await
                .is_none()
        );
        assert!(!pairing.withdraw(&opened.request_id, Some("wrong")).await);
        assert!(
            pairing
                .withdraw(&opened.request_id, Some(&opened.poll_token))
                .await
        );
        assert!(pairing.overview().await.requests.is_empty());
        assert!(
            !pairing
                .withdraw(&opened.request_id, Some(&opened.poll_token))
                .await
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_address_opens_five_requests_in_five_minutes_and_no_more_than_three_at_once() {
        let (pairing, _) = pairing().await;

        let mut opened = vec![];
        for _ in 0..3 {
            opened.push(pairing.open("a", &"A".repeat(64), addr(1)).await.unwrap());
        }
        assert!(pairing.open("a", &"A".repeat(64), addr(1)).await.is_none());
        assert!(pairing.open("a", &"A".repeat(64), addr(2)).await.is_some());

        for request in &opened {
            assert!(
                pairing
                    .withdraw(&request.request_id, Some(&request.poll_token))
                    .await
            );
        }
        for _ in 0..2 {
            assert!(pairing.open("a", &"A".repeat(64), addr(1)).await.is_some());
        }
        // Five opens, withdrawn or not, are all the address gets for five minutes.
        let latest = pairing.open("a", &"A".repeat(64), addr(1)).await;
        assert!(latest.is_none());
        tokio::time::advance(Duration::from_secs(301)).await;
        assert!(pairing.open("a", &"A".repeat(64), addr(1)).await.is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn ten_revealed_requests_fill_the_server_and_the_eleventh_cannot_reveal() {
        let (pairing, state) = pairing().await;
        for i in 0..10u8 {
            revealed(&pairing, &state, addr(i + 1)).await;
        }
        let nonce = new_nonce().unwrap();
        assert!(
            pairing
                .open("a", &commitment_of(&nonce), addr(50))
                .await
                .is_none()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_server_takes_sixty_reveals_in_five_minutes() {
        let (pairing, state) = pairing().await;
        for i in 0..60u32 {
            let from = IpAddr::V4(Ipv4Addr::new(10, 1, (i / 200) as u8, (i % 200) as u8 + 1));
            let (opened, _) = revealed(&pairing, &state, from).await;
            pairing
                .withdraw(&opened.request_id, Some(&opened.poll_token))
                .await;
        }

        assert!(pairing.overview().await.budget_exhausted);
        assert!(pairing.open("a", &"A".repeat(64), addr(99)).await.is_none());
        tokio::time::advance(Duration::from_secs(301)).await;
        assert!(!pairing.overview().await.budget_exhausted);
        assert!(pairing.open("a", &"A".repeat(64), addr(99)).await.is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn the_sweep_tells_the_app_when_a_waiting_request_ran_out() {
        let events = Events::new(vec![]);
        let mut listener = events.subscribe();
        let state = ServerState::start(
            Arc::new(InMemoryStore::new()),
            false,
            "pi-lab".into(),
            "t".into(),
            events,
        )
        .await
        .unwrap();
        let pairing = Pairing::new(state.clone());
        revealed(&pairing, &state, addr(1)).await;
        assert!(
            matches!(listener.try_recv(), Ok(ServerEvent::Pairing(o)) if o.requests.len() == 1)
        );

        tokio::time::advance(Duration::from_secs(301)).await;
        pairing.sweep().await;

        assert!(
            matches!(listener.try_recv(), Ok(ServerEvent::Pairing(o)) if o.requests.is_empty())
        );
    }

    /// A store whose saves can be held up or made to fail.
    struct TestStore {
        inner: InMemoryStore,
        hold: std::sync::atomic::AtomicBool,
        fail: std::sync::atomic::AtomicBool,
        entered: tokio::sync::Notify,
        gate: tokio::sync::Notify,
    }

    impl TestStore {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: InMemoryStore::new(),
                hold: false.into(),
                fail: false.into(),
                entered: tokio::sync::Notify::new(),
                gate: tokio::sync::Notify::new(),
            })
        }
    }

    impl crate::store::SkakelStore for TestStore {
        fn load(&self) -> crate::store::StoreFuture<'_, Option<crate::store::SkakelState>> {
            self.inner.load()
        }

        fn save<'a>(
            &'a self,
            state: &'a crate::store::SkakelState,
        ) -> crate::store::StoreFuture<'a, ()> {
            use std::sync::atomic::Ordering::SeqCst;
            Box::pin(async move {
                if self.fail.load(SeqCst) {
                    return Err(std::io::Error::other("the disk is gone"));
                }
                if self.hold.load(SeqCst) {
                    self.entered.notify_one();
                    self.gate.notified().await;
                }
                self.inner.save(state).await
            })
        }
    }

    async fn pairing_on(store: Arc<TestStore>) -> (Pairing, Arc<ServerState>) {
        let state = ServerState::start(
            store,
            false,
            "pi-lab".into(),
            "test-app".into(),
            Events::new(vec![]),
        )
        .await
        .unwrap();
        (Pairing::new(state.clone()), state)
    }

    #[tokio::test(start_paused = true)]
    async fn addresses_in_one_ipv6_64_share_the_per_address_open_budget() {
        let (pairing, _) = pairing().await;
        let commitment = commitment_of(&new_nonce().unwrap());

        for last in 1..=OPENS_PER_ADDRESS_PER_WINDOW {
            // Open requests per address are capped at three, so let each lapse unrevealed.
            let from: IpAddr = format!("2001:db8:1:2::{last}").parse().unwrap();
            assert!(pairing.open("lab pc", &commitment, from).await.is_some());
            tokio::time::advance(UNREVEALED_LIFETIME).await;
        }

        let sixth: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        assert!(pairing.open("lab pc", &commitment, sixth).await.is_none());
        let other_64: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert!(
            pairing
                .open("lab pc", &commitment, other_64)
                .await
                .is_some()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_app_sees_the_whole_address_a_request_came_from() {
        let (pairing, state) = pairing().await;
        let from: IpAddr = "2001:db8:1:2::7".parse().unwrap();

        revealed(&pairing, &state, from).await;

        assert_eq!(pairing.overview().await.requests[0].from, "2001:db8:1:2::7");
    }

    #[tokio::test(start_paused = true)]
    async fn opens_that_never_reveal_are_capped_for_the_whole_server() {
        let (pairing, _) = pairing().await;
        let commitment = commitment_of(&new_nonce().unwrap());

        for n in 0..MAX_UNREVEALED {
            let from = IpAddr::V4(Ipv4Addr::new(10, 1, (n / 200) as u8, (n % 200) as u8 + 1));
            assert!(pairing.open("lab pc", &commitment, from).await.is_some());
        }

        let next = IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1));
        assert!(pairing.open("lab pc", &commitment, next).await.is_none());
        tokio::time::advance(UNREVEALED_LIFETIME).await;
        assert!(pairing.open("lab pc", &commitment, next).await.is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn a_nonce_shorter_than_a_clients_is_not_taken() {
        let (pairing, _) = pairing().await;
        let short = "abc123";
        let opened = pairing
            .open("lab pc", &commitment_of(short), addr(1))
            .await
            .unwrap();

        assert_eq!(
            pairing.reveal(&opened.request_id, short).await,
            Reveal::NotFound
        );
        assert!(pairing.overview().await.requests.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_store_does_not_stall_the_other_calls_while_a_code_is_approved() {
        let store = TestStore::new();
        let (pairing, state) = pairing_on(store.clone()).await;
        let (opened, code) = revealed(&pairing, &state, addr(1)).await;
        store.hold.store(true, std::sync::atomic::Ordering::SeqCst);

        let approving = {
            let pairing = pairing.clone();
            let id = opened.request_id.clone();
            tokio::spawn(async move { pairing.approve(&id, &code).await })
        };
        store.entered.notified().await;

        let overview = tokio::time::timeout(Duration::from_secs(1), pairing.overview()).await;
        let other = tokio::time::timeout(
            Duration::from_secs(1),
            pairing.open("lab pc", &commitment_of(&new_nonce().unwrap()), addr(2)),
        )
        .await;
        assert!(overview.is_ok(), "overview waited for the store");
        assert!(other.is_ok(), "open waited for the store");

        store.gate.notify_one();
        assert_eq!(approving.await.unwrap().unwrap(), Approval::Approved);
        let poll = pairing
            .poll(&opened.request_id, Some(opened.poll_token.as_str()))
            .await
            .unwrap();
        assert_eq!(poll.state, PairState::Approved);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_save_leaves_the_request_waiting_for_another_try() {
        let store = TestStore::new();
        let (pairing, state) = pairing_on(store.clone()).await;
        let (opened, code) = revealed(&pairing, &state, addr(1)).await;
        store.fail.store(true, std::sync::atomic::Ordering::SeqCst);

        assert!(pairing.approve(&opened.request_id, &code).await.is_err());
        assert_eq!(pairing.overview().await.requests[0].state, "waiting");

        store.fail.store(false, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            pairing.approve(&opened.request_id, &code).await.unwrap(),
            Approval::Approved
        );
    }
}
