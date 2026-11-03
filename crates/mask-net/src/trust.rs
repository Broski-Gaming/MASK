//! The set of relays a component trusts, and their health.
//!
//! Relays, clients, and hidden-service hosts all need the same answers:
//! "which relays exist?", "is this Noise key a trusted relay?", "where is
//! the relay with identity X?". [`TrustedRelays`] answers them from one of
//! three sources:
//!
//! - **Folder** (local mode, one machine): `runtime/directory/*.json` written
//!   by relays. The folder is trusted completely, as in v0.5.
//! - **Consensus** (network mode, v0.6): the relay list from the newest
//!   consensus signed by a pinned directory authority
//!   (see [`crate::authority`]). Nothing is trusted until one is installed.
//! - **Static**: a fixed list given in code (tests).
//!
//! Every descriptor's own signature is verified; descriptors outside the
//! network scope are dropped. Folder and consensus sources also **pin
//! identities**: once a nickname has been seen with one Ed25519 identity, a
//! later descriptor claiming that nickname with a different identity is
//! refused for the rest of the process (the authority's allowlist enforces
//! the same rule durably).
//!
//! [`Health`] remembers relays that recently failed so path selection can
//! route around them.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

use tracing::warn;

use crate::NetError;
use crate::descriptor::{Directory, RelayDescriptor};
use crate::identity::NodeId;
use crate::scope::NetworkScope;

/// How long a relay is avoided after a failure.
pub const DEFAULT_PENALTY: Duration = Duration::from_secs(60);
/// Folder sources reload at most this often when a lookup misses (local
/// mode only: the folder is a handful of small files on this machine).
const RELOAD_INTERVAL: Duration = Duration::ZERO;

#[derive(Clone, Debug)]
enum Source {
    Static,
    Folder(PathBuf),
    Consensus,
}

#[derive(Default)]
struct State {
    relays: Vec<RelayDescriptor>,
    /// nickname → identity, for identity-change detection.
    pins: HashMap<String, NodeId>,
    /// Sequence number of the installed consensus (rollback protection).
    consensus_sequence: Option<u64>,
    /// Unix time after which the installed consensus is no longer valid.
    valid_until: Option<u64>,
    /// Unix time after which a newer consensus should be fetched.
    fresh_until: Option<u64>,
    last_reload: Option<Instant>,
    /// Descriptors refused because of identity changes (for diagnostics).
    identity_changes_refused: u64,
}

/// Shared, cheaply cloneable view of the trusted relays.
#[derive(Clone)]
pub struct TrustedRelays {
    source: Arc<Source>,
    scope: NetworkScope,
    state: Arc<RwLock<State>>,
    health: Health,
    /// Consensus sources: fired when a lookup misses, so a refresher can
    /// fetch a newer consensus early (a relay may have just been admitted).
    missed: Arc<Notify>,
}

impl std::fmt::Debug for TrustedRelays {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TrustedRelays({:?}, scope {})", self.source, self.scope)
    }
}

impl From<PathBuf> for TrustedRelays {
    /// A folder source in the loopback scope (v0.5 behaviour).
    fn from(dir: PathBuf) -> Self {
        Self::folder(dir, NetworkScope::Loopback)
    }
}

impl TrustedRelays {
    fn with_source(source: Source, scope: NetworkScope) -> Self {
        Self {
            source: Arc::new(source),
            scope,
            state: Arc::default(),
            health: Health::default(),
            missed: Arc::new(Notify::new()),
        }
    }

    /// Resolves after a lookup in a consensus source found nothing.
    pub async fn lookup_missed(&self) {
        self.missed.notified().await;
    }

    /// An empty set that tests fill with [`insert`](Self::insert).
    pub fn fixed(scope: NetworkScope) -> Self {
        Self::with_source(Source::Static, scope)
    }

    /// Descriptors from a local folder, re-read on every snapshot.
    pub fn folder(dir: PathBuf, scope: NetworkScope) -> Self {
        Self::with_source(Source::Folder(dir), scope)
    }

    /// Relays from signed consensus documents (network mode). Empty until
    /// [`install_consensus`](Self::install_consensus) succeeds.
    pub fn consensus(scope: NetworkScope) -> Self {
        Self::with_source(Source::Consensus, scope)
    }

    pub fn scope(&self) -> NetworkScope {
        self.scope
    }

    pub fn health(&self) -> &Health {
        &self.health
    }

    pub fn is_consensus(&self) -> bool {
        matches!(*self.source, Source::Consensus)
    }

    /// Add (or replace) one descriptor in a fixed set.
    pub fn insert(&self, descriptor: RelayDescriptor) {
        let mut state = self.state.write().unwrap();
        state.relays.retain(|d| d.node_id != descriptor.node_id);
        state.relays.push(descriptor);
    }

    /// Install the relays of a verified consensus with sequence number
    /// `sequence`, valid until `valid_until`. Older or equal sequences are
    /// refused (rollback), and so is a consensus with no relay usable here.
    pub fn install_consensus(
        &self,
        sequence: u64,
        fresh_until: u64,
        valid_until: u64,
        relays: Vec<RelayDescriptor>,
    ) -> Result<usize, NetError> {
        let mut state = self.state.write().unwrap();
        if state.consensus_sequence.is_some_and(|s| sequence <= s) {
            return Err(NetError::Untrusted(format!(
                "consensus {sequence} is not newer than the installed one (rollback refused)"
            )));
        }
        let accepted = self.filter(&mut state, relays);
        state.relays = accepted;
        state.consensus_sequence = Some(sequence);
        state.valid_until = Some(valid_until);
        state.fresh_until = Some(fresh_until);
        Ok(state.relays.len())
    }

    /// Consensus sources: true when no consensus is installed or the
    /// installed one is no longer fresh. Always false for other sources.
    pub fn needs_refresh(&self) -> bool {
        if !self.is_consensus() {
            return false;
        }
        let state = self.state.read().unwrap();
        state
            .fresh_until
            .is_none_or(|fresh| crate::service::now_secs() >= fresh)
    }

    /// Sequence number of the installed consensus, if any.
    pub fn consensus_sequence(&self) -> Option<u64> {
        self.state.read().unwrap().consensus_sequence
    }

    pub fn identity_changes_refused(&self) -> u64 {
        self.state.read().unwrap().identity_changes_refused
    }

    /// Apply the scope and identity-pin rules.
    fn filter(&self, state: &mut State, relays: Vec<RelayDescriptor>) -> Vec<RelayDescriptor> {
        let mut accepted: Vec<RelayDescriptor> = Vec::with_capacity(relays.len());
        for d in relays {
            if d.verify().is_err() {
                warn!(relay = %d.nickname, "dropping descriptor with a bad signature");
                continue;
            }
            if !self.scope.allows(d.addr) {
                warn!(relay = %d.nickname, addr = %d.addr, scope = %self.scope, "dropping relay outside the network scope");
                continue;
            }
            if !matches!(*self.source, Source::Static) {
                match state.pins.get(&d.nickname) {
                    Some(pinned) if *pinned != d.node_id => {
                        state.identity_changes_refused += 1;
                        warn!(
                            relay = %d.nickname,
                            pinned = %pinned.short(),
                            offered = %d.node_id.short(),
                            "refusing relay identity change"
                        );
                        continue;
                    }
                    Some(_) => {}
                    None => {
                        state.pins.insert(d.nickname.clone(), d.node_id);
                    }
                }
            }
            if accepted
                .iter()
                .any(|a| a.node_id == d.node_id || a.nickname == d.nickname)
            {
                warn!(relay = %d.nickname, "dropping duplicate relay");
                continue;
            }
            accepted.push(d);
        }
        accepted.sort_by(|a, b| a.nickname.cmp(&b.nickname));
        accepted
    }

    fn reload_folder(&self, force: bool) -> Result<(), NetError> {
        let Source::Folder(dir) = &*self.source else {
            return Ok(());
        };
        {
            let state = self.state.read().unwrap();
            if !force
                && state
                    .last_reload
                    .is_some_and(|t| t.elapsed() < RELOAD_INTERVAL)
            {
                return Ok(());
            }
        }
        let (loaded, problems) = Directory::load(dir)?;
        for problem in problems {
            warn!("relay directory: {problem}");
        }
        let mut state = self.state.write().unwrap();
        let accepted = self.filter(&mut state, loaded.relays().to_vec());
        state.relays = accepted;
        state.last_reload = Some(Instant::now());
        Ok(())
    }

    fn expired(&self) -> bool {
        let state = self.state.read().unwrap();
        state
            .valid_until
            .is_some_and(|until| crate::service::now_secs() > until)
    }

    /// The current relays as a [`Directory`] for path selection. Folder
    /// sources are re-read; an expired consensus yields an error.
    pub fn snapshot(&self) -> Result<Directory, NetError> {
        self.reload_folder(true)?;
        if self.is_consensus() {
            let state = self.state.read().unwrap();
            if state.consensus_sequence.is_none() {
                return Err(NetError::Untrusted(
                    "no valid consensus yet (is a directory authority reachable?)".into(),
                ));
            }
        }
        if self.expired() {
            return Err(NetError::Untrusted(
                "the relay consensus has expired (is a directory authority reachable?)".into(),
            ));
        }
        Directory::from_descriptors(self.state.read().unwrap().relays.clone())
    }

    fn find_where(&self, matches: impl Fn(&RelayDescriptor) -> bool) -> Option<RelayDescriptor> {
        let lookup = |this: &Self| {
            if this.expired() {
                return None;
            }
            this.state
                .read()
                .unwrap()
                .relays
                .iter()
                .find(|d| matches(d))
                .cloned()
        };
        if let Some(found) = lookup(self) {
            return Some(found);
        }
        if self.is_consensus() {
            self.missed.notify_one();
            return None;
        }
        // A relay that started after our last read of the folder.
        if self.reload_folder(false).is_ok() {
            return lookup(self);
        }
        None
    }

    /// The trusted relay with this identity.
    pub fn find(&self, node_id: &NodeId) -> Option<RelayDescriptor> {
        self.find_where(|d| d.node_id == *node_id)
    }

    /// The trusted relay whose current link key is `key`.
    pub fn find_by_link_key(&self, key: &[u8; 32]) -> Option<RelayDescriptor> {
        self.find_where(|d| d.link_key == *key)
    }
}

/// Relays that failed recently, shared by everything using one
/// [`TrustedRelays`].
#[derive(Clone, Default)]
pub struct Health {
    bad: Arc<Mutex<HashMap<NodeId, Instant>>>,
}

impl Health {
    /// Avoid `relay` for `penalty`.
    pub fn mark_failed(&self, relay: NodeId, penalty: Duration) {
        self.bad
            .lock()
            .unwrap()
            .insert(relay, Instant::now() + penalty);
    }

    /// Forget a failure (the relay worked).
    pub fn mark_ok(&self, relay: &NodeId) {
        self.bad.lock().unwrap().remove(relay);
    }

    /// Relays currently being avoided.
    pub fn unhealthy(&self) -> Vec<NodeId> {
        let now = Instant::now();
        let mut bad = self.bad.lock().unwrap();
        bad.retain(|_, until| *until > now);
        bad.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::RelayKeys;
    use crate::identity::Role;

    fn relay(nick: &str, addr: &str) -> (RelayKeys, RelayDescriptor) {
        let keys = RelayKeys::generate();
        let d = RelayDescriptor::sign(&keys, nick, Role::Middle, addr.parse().unwrap());
        (keys, d)
    }

    #[test]
    fn consensus_source_is_empty_until_installed_and_refuses_rollback() {
        let trusted = TrustedRelays::consensus(NetworkScope::Loopback);
        assert!(trusted.snapshot().is_err());
        let (_, d) = relay("m1", "127.0.0.1:7102");
        let until = crate::service::now_secs() + 600;
        assert_eq!(
            trusted
                .install_consensus(5, until, until, vec![d.clone()])
                .unwrap(),
            1
        );
        assert_eq!(trusted.find(&d.node_id).unwrap(), d);
        assert_eq!(trusted.find_by_link_key(&d.link_key).unwrap(), d);
        assert!(trusted.install_consensus(5, until, until, vec![]).is_err());
        assert!(trusted.install_consensus(4, until, until, vec![]).is_err());
        assert_eq!(trusted.snapshot().unwrap().relays().len(), 1);
    }

    #[test]
    fn expired_consensus_is_not_used() {
        let trusted = TrustedRelays::consensus(NetworkScope::Loopback);
        let (_, d) = relay("m1", "127.0.0.1:7102");
        trusted.install_consensus(1, 1, 1, vec![d.clone()]).unwrap();
        assert!(trusted.snapshot().is_err());
        assert!(trusted.find(&d.node_id).is_none());
    }

    #[test]
    fn identity_change_for_a_known_nickname_is_refused() {
        let trusted = TrustedRelays::consensus(NetworkScope::Loopback);
        let until = crate::service::now_secs() + 600;
        let (_, original) = relay("m1", "127.0.0.1:7102");
        let (_, impostor) = relay("m1", "127.0.0.1:7102");
        trusted
            .install_consensus(1, until, until, vec![original.clone()])
            .unwrap();
        trusted
            .install_consensus(2, until, until, vec![impostor.clone()])
            .unwrap();
        assert!(trusted.find(&impostor.node_id).is_none());
        assert_eq!(trusted.identity_changes_refused(), 1);
        // The real relay with a new onion/link key (restart) is fine.
        trusted
            .install_consensus(3, until, until, vec![original.clone()])
            .unwrap();
        assert!(trusted.find(&original.node_id).is_some());
    }

    #[test]
    fn relays_outside_the_scope_are_dropped() {
        let trusted = TrustedRelays::consensus(NetworkScope::Loopback);
        let until = crate::service::now_secs() + 600;
        let (_, lan) = relay("lan", "192.168.1.9:7102");
        let (_, public) = relay("pub", "8.8.8.8:7102");
        let (_, local) = relay("local", "127.0.0.1:7102");
        assert_eq!(
            trusted
                .install_consensus(1, until, until, vec![lan, public, local])
                .unwrap(),
            1
        );

        let private = TrustedRelays::consensus(NetworkScope::Private);
        let (_, lan) = relay("lan", "192.168.1.9:7102");
        let (_, public) = relay("pub", "8.8.8.8:7102");
        assert_eq!(
            private
                .install_consensus(1, until, until, vec![lan, public])
                .unwrap(),
            1
        );
    }

    #[test]
    fn health_penalties_expire() {
        let health = Health::default();
        let id = RelayKeys::generate().node_id();
        health.mark_failed(id, Duration::from_millis(30));
        assert_eq!(health.unhealthy(), vec![id]);
        std::thread::sleep(Duration::from_millis(50));
        assert!(health.unhealthy().is_empty());
    }
}
