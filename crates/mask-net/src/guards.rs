//! Persistent entry guards (v0.7).
//!
//! **Why.** If a client picked a fresh random entry relay for every circuit,
//! then over time it would use *every* entry relay, including any run by an
//! attacker, and an attacker who also controls (or watches) the last hop
//! could match traffic at both ends. With guards a client uses only a few
//! entry relays for months: either none of them is hostile (and that client
//! is safe from this attack), or one is. This is the reasoning behind Tor's
//! guards; MASK uses a simplified version of Tor's guard algorithm.
//!
//! **Algorithm.**
//! - The client *samples* up to [`GuardConfig::max_sampled`] entry relays
//!   over its lifetime, in order. The first [`GuardConfig::primary`] usable
//!   ones are its *primary* guards; others are used only while the primaries
//!   are down or unsuitable.
//! - New guards are chosen at random, preferring entry relays the authority
//!   has listed for at least [`GuardConfig::min_listed`] (relays added in a
//!   hurry, as an attacker would, are not preferred), and relays in a
//!   family, operator, and /16 network not already among the guards.
//! - Each guard is kept for a random 30-60 days, then replaced.
//! - A guard that fails is skipped for [`GuardConfig::retry_after`], then
//!   tried again. **When every sampled guard is down, no new guard is
//!   picked:** the client fails closed. Otherwise an attacker who can block
//!   connections could make the client try entry relays until it reaches
//!   one of theirs. (Delete the guard file to start over deliberately.)
//! - A circuit's entry guard must not be related to its last hop (same
//!   relay, family, or operator, see
//!   [`RelayDescriptor::related_to`]). If no sampled guard qualifies, the
//!   circuit is refused instead of using an unrelated entry.
//!
//! **Storage.** [`Guards::persistent`] keeps the state in a JSON file (mode
//! 0600 in a 0700 folder): the guards' identities and nicknames, when they
//! were added, when they expire, and recent failures. It reveals which entry
//! relays this client uses, so it is private, like a key file. Files are
//! per network (a guard set never mixes networks).

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::NetError;
use crate::descriptor::{Directory, RelayDescriptor};
use crate::identity::{NodeId, Role, from_hex, to_hex};
use crate::service::now_secs;

const FILE_VERSION: u16 = 1;
/// A guard file never holds more guards than this (corrupt-file guard).
const MAX_RECORDS: usize = 64;
const DAY: u64 = 86_400;

#[derive(Clone, Copy, Debug)]
pub struct GuardConfig {
    /// Guards used in preference to all others.
    pub primary: usize,
    /// Most entry relays ever sampled (until guards expire).
    pub max_sampled: usize,
    /// A guard is kept for a random time in this range.
    pub lifetime: (Duration, Duration),
    /// How long a failed guard is skipped before it is tried again.
    pub retry_after: Duration,
    /// Prefer new guards the authority has listed at least this long
    /// (`network.toml` `[relay_policy] guard_min_listed_secs`).
    pub min_listed: Duration,
}

impl GuardConfig {
    /// Defaults with the network's `[relay_policy] guard_min_listed_secs`.
    pub fn for_network(network: &crate::config::NetworkConfig) -> Self {
        Self {
            min_listed: Duration::from_secs(network.relay_policy.guard_min_listed_secs),
            ..Self::default()
        }
    }
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            primary: 2,
            max_sampled: 5,
            lifetime: (Duration::from_secs(30 * DAY), Duration::from_secs(60 * DAY)),
            retry_after: Duration::from_secs(600),
            min_listed: Duration::ZERO,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Record {
    identity: String,
    nickname: String,
    added: u64,
    expires: u64,
    /// A circuit through this guard has worked at least once.
    confirmed: bool,
    /// Skip until this time (Unix seconds); 0 = usable.
    failed_until: u64,
}

impl Record {
    fn id(&self) -> Option<NodeId> {
        from_hex::<32>(&self.identity).map(NodeId::from_bytes)
    }
}

#[derive(Serialize, Deserialize)]
struct GuardFile {
    version: u16,
    network: String,
    guards: Vec<Record>,
}

/// A public view of one guard, for status displays and tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardInfo {
    pub identity: NodeId,
    pub nickname: String,
    pub confirmed: bool,
    pub failing: bool,
}

struct State {
    guards: Vec<Record>,
}

/// One client's entry guards. Cheap to clone; clones share the state.
#[derive(Clone)]
pub struct Guards {
    state: Arc<Mutex<State>>,
    config: GuardConfig,
    file: Option<Arc<PathBuf>>,
    network: Arc<String>,
}

impl std::fmt::Debug for Guards {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.file {
            Some(path) => write!(f, "Guards({})", path.display()),
            None => write!(f, "Guards(in memory)"),
        }
    }
}

impl Guards {
    /// Guards kept in memory for this process only.
    pub fn ephemeral(config: GuardConfig) -> Self {
        Self {
            state: Arc::new(Mutex::new(State { guards: Vec::new() })),
            config,
            file: None,
            network: Arc::new(String::new()),
        }
    }

    /// Guards stored in `path` for the network named `network` (use
    /// `"local"` in local mode). The folder is created with mode 0700 and
    /// the file with 0600; a file readable by others, or belonging to
    /// another network, is refused.
    pub fn persistent(path: &Path, network: &str, config: GuardConfig) -> Result<Self, NetError> {
        let guards = match fs::metadata(path) {
            Ok(meta) => {
                if meta.permissions().mode() & 0o077 != 0 {
                    return Err(NetError::InvalidConfig(format!(
                        "{} is accessible by other users; run: chmod 600 {}",
                        path.display(),
                        path.display()
                    )));
                }
                let text = fs::read_to_string(path)?;
                let file: GuardFile = serde_json::from_str(&text).map_err(|e| {
                    NetError::InvalidConfig(format!(
                        "{}: unreadable guard file ({e}); delete it to choose new guards",
                        path.display()
                    ))
                })?;
                if file.version != FILE_VERSION
                    || file.guards.len() > MAX_RECORDS
                    || file.guards.iter().any(|g| g.id().is_none())
                {
                    return Err(NetError::InvalidConfig(format!(
                        "{}: invalid guard file; delete it to choose new guards",
                        path.display()
                    )));
                }
                if file.network != network {
                    return Err(NetError::InvalidConfig(format!(
                        "{} holds guards for network \"{}\", not \"{network}\"",
                        path.display(),
                        file.network
                    )));
                }
                file.guards
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        if let Some(dir) = path.parent() {
            crate::crypto::keys::create_private_dir(dir, true)?;
        }
        let this = Self {
            state: Arc::new(Mutex::new(State { guards })),
            config,
            file: Some(Arc::new(path.to_owned())),
            network: Arc::new(network.to_owned()),
        };
        this.save(&this.state.lock().unwrap())?;
        Ok(this)
    }

    /// `<dir>/<who>-guards-<network>.json`, persistent (see
    /// [`persistent`](Self::persistent)). `who` names the component
    /// (`client`, `browser`, `service`) so each keeps its own guards:
    /// sharing guards would link a machine's browsing to its services.
    pub fn open_in(
        dir: &Path,
        who: &str,
        network: &str,
        config: GuardConfig,
    ) -> Result<Self, NetError> {
        Self::persistent(
            &dir.join(format!("{who}-guards-{network}.json")),
            network,
            config,
        )
    }

    pub fn config(&self) -> &GuardConfig {
        &self.config
    }

    /// The sampled guards, primary first.
    pub fn list(&self) -> Vec<GuardInfo> {
        let now = now_secs();
        self.state
            .lock()
            .unwrap()
            .guards
            .iter()
            .filter_map(|g| {
                Some(GuardInfo {
                    identity: g.id()?,
                    nickname: g.nickname.clone(),
                    confirmed: g.confirmed,
                    failing: g.failed_until > now,
                })
            })
            .collect()
    }

    fn save(&self, state: &State) -> Result<(), NetError> {
        let Some(path) = &self.file else {
            return Ok(());
        };
        let file = GuardFile {
            version: FILE_VERSION,
            network: (*self.network).clone(),
            guards: state.guards.clone(),
        };
        let tmp = path.with_extension("json.tmp");
        let _ = fs::remove_file(&tmp);
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        out.write_all(
            serde_json::to_string_pretty(&file)
                .expect("serializes")
                .as_bytes(),
        )?;
        out.sync_all()?;
        fs::rename(&tmp, path.as_ref())?;
        Ok(())
    }

    /// The entry guard to use for a circuit ending at `last`.
    ///
    /// Samples guards as needed (within the limits), then returns the first
    /// guard, in order, that is listed in `directory` as an entry relay, is
    /// not failing or in `unhealthy`, and is not related to `last`.
    pub fn choose(
        &self,
        directory: &Directory,
        last: &RelayDescriptor,
        unhealthy: &[NodeId],
    ) -> Result<RelayDescriptor, NetError> {
        let now = now_secs();
        let mut state = self.state.lock().unwrap();
        let mut changed = self.expire(&mut state, now);
        changed |= self.top_up(&mut state, directory, now);

        let mut sampled_more = false;
        let result = loop {
            let mut reasons = Vec::new();
            let mut found = None;
            for record in &state.guards {
                let Some(id) = record.id() else { continue };
                let Some(guard) = directory.find(&id).filter(|d| d.role == Role::Entry) else {
                    reasons.push(format!("{} is not listed", record.nickname));
                    continue;
                };
                if record.failed_until > now || unhealthy.contains(&id) {
                    reasons.push(format!("{} is failing", record.nickname));
                    continue;
                }
                if guard.related_to(last) {
                    reasons.push(format!(
                        "{} shares a family or operator with {}",
                        record.nickname, last.nickname
                    ));
                    continue;
                }
                found = Some(guard.clone());
                break;
            }
            if let Some(guard) = found {
                break Ok(guard);
            }
            // Nothing usable. Sample one more guard only if some sampled
            // guard is unsuitable for *this* last hop (not merely down):
            // never because guards are failing (see the module docs).
            let all_down = state
                .guards
                .iter()
                .all(|g| g.failed_until > now || g.id().is_some_and(|id| unhealthy.contains(&id)));
            if !all_down && !sampled_more && self.sample_one(&mut state, directory, now) {
                sampled_more = true;
                changed = true;
                continue;
            }
            break Err(NetError::NoGuard(if state.guards.is_empty() {
                "no entry relay is available".into()
            } else if all_down {
                format!(
                    "all {} entry guard(s) are unreachable ({}); not choosing new ones \
                     (delete the guard file to reset deliberately)",
                    state.guards.len(),
                    reasons.join("; ")
                )
            } else {
                format!(
                    "no entry guard can be used with last hop {} ({})",
                    last.nickname,
                    reasons.join("; ")
                )
            }));
        };
        self.finish(state, changed, result)
    }

    fn finish(
        &self,
        state: std::sync::MutexGuard<'_, State>,
        changed: bool,
        result: Result<RelayDescriptor, NetError>,
    ) -> Result<RelayDescriptor, NetError> {
        if changed && let Err(e) = self.save(&state) {
            warn!(error = %e, "could not save entry guards");
        }
        result
    }

    /// The first usable primary guard, if any (to steer last-hop choice
    /// away from its family).
    pub fn preferred(
        &self,
        directory: &Directory,
        unhealthy: &[NodeId],
    ) -> Option<RelayDescriptor> {
        let now = now_secs();
        let mut state = self.state.lock().unwrap();
        let changed = self.expire(&mut state, now) | self.top_up(&mut state, directory, now);
        let found = state.guards.iter().find_map(|g| {
            let id = g.id()?;
            if g.failed_until > now || unhealthy.contains(&id) {
                return None;
            }
            directory
                .find(&id)
                .filter(|d| d.role == Role::Entry)
                .cloned()
        });
        if changed && let Err(e) = self.save(&state) {
            warn!(error = %e, "could not save entry guards");
        }
        found
    }

    /// Skip `guard` for [`GuardConfig::retry_after`].
    pub fn mark_failed(&self, guard: &NodeId) {
        let until = now_secs() + self.config.retry_after.as_secs().max(1);
        self.update(guard, |g| g.failed_until = until);
    }

    /// A circuit through `guard` worked.
    pub fn mark_ok(&self, guard: &NodeId) {
        self.update(guard, |g| {
            g.confirmed = true;
            g.failed_until = 0;
        });
    }

    fn update(&self, guard: &NodeId, change: impl FnOnce(&mut Record)) {
        let mut state = self.state.lock().unwrap();
        let hex = to_hex(guard.as_bytes());
        let Some(record) = state.guards.iter_mut().find(|g| g.identity == hex) else {
            return;
        };
        let before = record.clone();
        change(record);
        if *record != before
            && let Err(e) = self.save(&state)
        {
            warn!(error = %e, "could not save entry guards");
        }
    }

    /// Drop guards past their lifetime.
    fn expire(&self, state: &mut State, now: u64) -> bool {
        let before = state.guards.len();
        state.guards.retain(|g| {
            let keep = g.expires > now;
            if !keep {
                info!(guard = %g.nickname, "entry guard reached the end of its lifetime");
            }
            keep
        });
        before != state.guards.len()
    }

    /// Sample until there are `primary` listed guards (within the limits).
    fn top_up(&self, state: &mut State, directory: &Directory, now: u64) -> bool {
        let mut changed = false;
        loop {
            let listed = state
                .guards
                .iter()
                .filter(|g| {
                    g.id()
                        .and_then(|id| directory.find(&id))
                        .is_some_and(|d| d.role == Role::Entry)
                })
                .count();
            if listed >= self.config.primary || !self.sample_one(state, directory, now) {
                return changed;
            }
            changed = true;
        }
    }

    /// Add one random entry relay as a new guard. Returns false if the
    /// sample is full or no unsampled entry relay exists.
    fn sample_one(&self, state: &mut State, directory: &Directory, now: u64) -> bool {
        if state.guards.len() >= self.config.max_sampled {
            return false;
        }
        let sampled: Vec<NodeId> = state.guards.iter().filter_map(Record::id).collect();
        let current: Vec<&RelayDescriptor> =
            sampled.iter().filter_map(|id| directory.find(id)).collect();
        let candidates: Vec<&RelayDescriptor> = directory
            .relays()
            .iter()
            .filter(|d| d.role == Role::Entry && !sampled.contains(&d.node_id))
            .collect();
        if candidates.is_empty() {
            return false;
        }
        let min_listed = self.config.min_listed.as_secs();
        let established = |d: &&RelayDescriptor| {
            d.listed_since > 0 && d.listed_since.saturating_add(min_listed) <= now
        };
        let diverse = |d: &&RelayDescriptor| {
            current
                .iter()
                .all(|c| !d.related_to(c) && !d.same_subnet(c))
        };
        let unrelated = |d: &&RelayDescriptor| current.iter().all(|c| !d.related_to(c));
        let tiers: [Vec<&RelayDescriptor>; 5] = [
            candidates
                .iter()
                .copied()
                .filter(|d| established(d) && diverse(d))
                .collect(),
            candidates
                .iter()
                .copied()
                .filter(|d| established(d) && unrelated(d))
                .collect(),
            candidates.iter().copied().filter(established).collect(),
            candidates.iter().copied().filter(unrelated).collect(),
            candidates.clone(),
        ];
        let pool = tiers
            .into_iter()
            .find(|t| !t.is_empty())
            .expect("non-empty");
        let index = u64::from_le_bytes(crate::crypto::random_bytes::<8>()) as usize % pool.len();
        let chosen = pool[index];
        let (min, max) = self.config.lifetime;
        let span = max.as_secs().saturating_sub(min.as_secs()).max(1);
        let lifetime =
            min.as_secs() + u64::from_le_bytes(crate::crypto::random_bytes::<8>()) % span;
        info!(guard = %chosen.nickname, "new entry guard");
        state.guards.push(Record {
            identity: to_hex(chosen.node_id.as_bytes()),
            nickname: chosen.nickname.clone(),
            added: now,
            expires: now + lifetime,
            confirmed: false,
            failed_until: 0,
        });
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::RelayKeys;

    fn relay(nick: &str, role: Role, port: u16, family: &str) -> RelayDescriptor {
        let mut d = RelayDescriptor::sign_with_family(
            &RelayKeys::generate(),
            nick,
            role,
            format!("10.0.{port}.1:{port}").parse().unwrap(),
            family,
        );
        d.listed_since = 1;
        d
    }

    fn config() -> GuardConfig {
        GuardConfig {
            retry_after: Duration::from_secs(600),
            ..GuardConfig::default()
        }
    }

    fn net(entries: usize) -> (Directory, RelayDescriptor) {
        let mut relays: Vec<RelayDescriptor> = (0..entries)
            .map(|i| {
                relay(
                    &format!("e{i}"),
                    Role::Entry,
                    100 + i as u16,
                    &format!("f{i}"),
                )
            })
            .collect();
        let last = relay("rv", Role::Rendezvous, 200, "frv");
        relays.push(last.clone());
        (Directory::from_descriptors(relays).unwrap(), last)
    }

    #[test]
    fn the_same_guard_is_used_for_every_circuit() {
        let (dir, last) = net(10);
        let guards = Guards::ephemeral(config());
        let first = guards.choose(&dir, &last, &[]).unwrap();
        for _ in 0..50 {
            assert_eq!(guards.choose(&dir, &last, &[]).unwrap(), first);
        }
        assert_eq!(guards.list().len(), 2, "two primary guards sampled");
    }

    #[test]
    fn a_failed_guard_falls_back_to_the_next_and_comes_back() {
        let (dir, last) = net(10);
        let guards = Guards::ephemeral(GuardConfig {
            retry_after: Duration::from_secs(1),
            ..config()
        });
        let first = guards.choose(&dir, &last, &[]).unwrap();
        guards.mark_failed(&first.node_id);
        let second = guards.choose(&dir, &last, &[]).unwrap();
        assert_ne!(second, first);
        assert_eq!(
            guards.list().len(),
            2,
            "the second primary, not a new sample"
        );
        std::thread::sleep(Duration::from_millis(2100));
        assert_eq!(guards.choose(&dir, &last, &[]).unwrap(), first);
    }

    #[test]
    fn when_every_guard_is_down_no_new_guard_is_chosen() {
        // Fail-closed: an attacker blocking guards must not be able to make
        // the client walk through every entry relay.
        let (dir, last) = net(10);
        let guards = Guards::ephemeral(config());
        for _ in 0..20 {
            match guards.choose(&dir, &last, &[]) {
                Ok(g) => guards.mark_failed(&g.node_id),
                Err(e) => {
                    assert!(matches!(e, NetError::NoGuard(_)), "{e}");
                    break;
                }
            }
        }
        assert_eq!(guards.list().len(), 2, "only the primaries were ever tried");
        assert!(guards.choose(&dir, &last, &[]).is_err());
    }

    #[test]
    fn guard_and_last_hop_are_never_related() {
        // Two entries: one shares the last hop's family.
        let e_same = relay("e-same", Role::Entry, 100, "frv");
        let e_other = relay("e-other", Role::Entry, 101, "f1");
        let last = relay("rv", Role::Rendezvous, 200, "frv");
        let dir = Directory::from_descriptors(vec![e_same, e_other.clone(), last.clone()]).unwrap();
        let guards = Guards::ephemeral(config());
        for _ in 0..20 {
            assert_eq!(guards.choose(&dir, &last, &[]).unwrap(), e_other);
        }
        // With only the related entry left, the circuit is refused.
        let dir = Directory::from_descriptors(vec![
            relay("e-same2", Role::Entry, 102, "frv"),
            last.clone(),
        ])
        .unwrap();
        let guards = Guards::ephemeral(config());
        let err = guards.choose(&dir, &last, &[]).unwrap_err().to_string();
        assert!(err.contains("shares a family"), "{err}");
    }

    #[test]
    fn new_guards_prefer_established_and_diverse_entries() {
        let now = now_secs();
        let mut old_a = relay("old-a", Role::Entry, 100, "fa");
        old_a.listed_since = now - 10 * DAY;
        let mut old_a2 = relay("old-a2", Role::Entry, 101, "fa");
        old_a2.listed_since = now - 10 * DAY;
        let mut old_b = relay("old-b", Role::Entry, 102, "fb");
        old_b.listed_since = now - 10 * DAY;
        let mut relays = vec![old_a, old_a2, old_b];
        // A flood of freshly listed entry relays (a Sybil attack).
        for i in 0..30 {
            let mut fresh = relay(&format!("fresh{i}"), Role::Entry, 110 + i, &format!("s{i}"));
            fresh.listed_since = now - 60;
            relays.push(fresh);
        }
        let last = relay("rv", Role::Rendezvous, 200, "frv");
        relays.push(last.clone());
        let dir = Directory::from_descriptors(relays).unwrap();
        for _ in 0..20 {
            let guards = Guards::ephemeral(GuardConfig {
                min_listed: Duration::from_secs(DAY),
                ..config()
            });
            guards.choose(&dir, &last, &[]).unwrap();
            let names: Vec<String> = guards.list().into_iter().map(|g| g.nickname).collect();
            assert!(names.iter().all(|n| n.starts_with("old")), "{names:?}");
            assert!(
                names.contains(&"old-b".to_owned()),
                "two families: {names:?}"
            );
        }
    }

    #[test]
    fn guards_persist_privately_and_per_network() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state/guards-testnet.json");
        let (directory, last) = net(10);
        let first = {
            let guards = Guards::persistent(&path, "testnet", config()).unwrap();
            guards.choose(&directory, &last, &[]).unwrap()
        };
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let folder = fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(folder & 0o777, 0o700);
        // A "restart": the same guard again.
        let guards = Guards::persistent(&path, "testnet", config()).unwrap();
        assert_eq!(guards.choose(&directory, &last, &[]).unwrap(), first);
        // Another network's file is refused, as is a readable one.
        assert!(Guards::persistent(&path, "othernet", config()).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Guards::persistent(&path, "testnet", config()).is_err());
    }

    #[test]
    fn expired_guards_are_replaced() {
        let (dir, last) = net(10);
        let guards = Guards::ephemeral(GuardConfig {
            lifetime: (Duration::from_secs(1), Duration::from_secs(2)),
            ..config()
        });
        guards.choose(&dir, &last, &[]).unwrap();
        for g in guards.list() {
            guards.mark_ok(&g.identity);
        }
        assert!(guards.list().iter().all(|g| g.confirmed));
        std::thread::sleep(Duration::from_millis(2100));
        guards.choose(&dir, &last, &[]).unwrap();
        // Fresh records (possibly for the same relays, chosen at random again).
        let after = guards.list();
        assert_eq!(after.len(), 2);
        assert!(
            after.iter().all(|g| !g.confirmed),
            "all replaced: {after:?}"
        );
    }
}
