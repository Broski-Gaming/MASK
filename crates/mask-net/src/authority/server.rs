//! The directory authority server.
//!
//! Three tasks run side by side:
//! - **accept**: Noise NK directory requests (bounded connections, idle and
//!   handshake timeouts, one message per request);
//! - **probe**: every `probe_interval`, a Noise `Probe` handshake to each
//!   admitted relay at its advertised address, using the link key in its
//!   descriptor. Two failures in a row remove the relay from the consensus
//!   until it answers again;
//! - **consensus**: re-sign the consensus every `consensus_interval`, and
//!   soon after the set of running relays changes.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{Instrument, debug, info, info_span, warn};

use super::consensus::{MAX_CONSENSUS_RELAYS, SignedConsensus, Validity};
use super::{
    AuthorityKeys, AuthorityStatus, DIR_PROTOCOL_VERSION, DirErrorCode, DirRequest, DirRequestBody,
    DirResponse, RelayStatus,
};
use crate::NetError;
use crate::address::MorpAddress;
use crate::config::{ApprovedRelays, NetworkConfig};
use crate::descriptor::RelayDescriptor;
use crate::directory::server::{DirectoryState, StoreError};
use crate::identity::NodeId;
use crate::protocol::{LinkMsg, MORP_VERSION, decode, encode};
use crate::service::now_secs;
use crate::transport::{ConnectPolicy, Connection, LinkKind, Timeouts};

/// Requests served on one connection before it is closed.
const MAX_REQUESTS_PER_CONNECTION: usize = 64;
/// Probe failures in a row before a relay leaves the consensus.
const MAX_PROBE_FAILURES: u32 = 2;

#[derive(Clone, Debug)]
pub struct AuthorityConfig {
    /// Must match an `[[authority]]` in `network`.
    pub name: String,
    pub listen: SocketAddr,
    pub network: NetworkConfig,
    pub approved: ApprovedRelays,
    pub consensus_interval: Duration,
    pub consensus_lifetime: Duration,
    pub probe_interval: Duration,
    /// A relay that has not re-uploaded its descriptor for this long is
    /// dropped (relays upload every minute by default).
    pub relay_expiry: Duration,
    pub timeouts: Timeouts,
    pub policy: ConnectPolicy,
    pub max_connections: usize,
}

impl AuthorityConfig {
    pub fn new(
        name: impl Into<String>,
        listen: SocketAddr,
        network: NetworkConfig,
        approved: ApprovedRelays,
    ) -> Self {
        Self {
            name: name.into(),
            listen,
            network,
            approved,
            consensus_interval: Duration::from_secs(60),
            consensus_lifetime: Duration::from_secs(600),
            probe_interval: Duration::from_secs(20),
            relay_expiry: Duration::from_secs(300),
            timeouts: Timeouts::default(),
            policy: ConnectPolicy::allow_all(),
            max_connections: 256,
        }
    }
}

struct RelayEntry {
    descriptor: RelayDescriptor,
    uploaded: Instant,
    last_probe: Option<Instant>,
    running: bool,
    failures: u32,
}

#[derive(Default)]
struct Counters {
    identity_changes_refused: AtomicU64,
    unapproved_uploads: AtomicU64,
    probes_ok: AtomicU64,
    probes_failed: AtomicU64,
    consensuses_signed: AtomicU64,
}

/// Counters, for tests and diagnostics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuthorityStats {
    pub admitted_relays: usize,
    pub running_relays: usize,
    pub identity_changes_refused: u64,
    pub unapproved_uploads: u64,
    pub probes_ok: u64,
    pub probes_failed: u64,
    pub consensuses_signed: u64,
}

struct Inner {
    keys: AuthorityKeys,
    config: AuthorityConfig,
    policy: ConnectPolicy,
    relays: Mutex<HashMap<NodeId, RelayEntry>>,
    services: DirectoryState,
    /// The current consensus, encoded, and its sequence and expiry.
    consensus: RwLock<Option<(Vec<u8>, u64, u64)>>,
    changed: Notify,
    connections: Arc<Semaphore>,
    counters: Counters,
    shutdown: CancellationToken,
    tasks: TaskTracker,
}

/// A bound authority, ready to [`serve`](Authority::serve).
pub struct Authority {
    inner: Arc<Inner>,
    listener: TcpListener,
}

#[derive(Clone)]
pub struct AuthorityHandle {
    inner: Arc<Inner>,
}

impl Authority {
    pub async fn bind(config: AuthorityConfig, keys: AuthorityKeys) -> Result<Self, NetError> {
        let scope = config.network.scope;
        scope.check(config.listen)?;
        let pinned = config
            .network
            .authorities
            .iter()
            .find(|a| a.name == config.name)
            .ok_or_else(|| {
                NetError::InvalidConfig(format!(
                    "network.toml has no authority named \"{}\"",
                    config.name
                ))
            })?;
        if pinned.identity != keys.identity_public() || pinned.link_key != keys.link_public() {
            return Err(NetError::InvalidConfig(format!(
                "the keys in network.toml for \"{}\" are not this authority's keys \
                 (run `mask-authority keys` and copy the printed lines)",
                config.name
            )));
        }
        let listener = TcpListener::bind(config.listen).await?;
        let policy = config.policy.clone().with_scope(scope);
        Ok(Self {
            inner: Arc::new(Inner {
                keys,
                policy,
                relays: Mutex::new(HashMap::new()),
                services: DirectoryState::default(),
                consensus: RwLock::new(None),
                changed: Notify::new(),
                connections: Arc::new(Semaphore::new(config.max_connections)),
                counters: Counters::default(),
                shutdown: CancellationToken::new(),
                tasks: TaskTracker::new(),
                config,
            }),
            listener,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.listener.local_addr().expect("bound listener")
    }

    pub fn handle(&self) -> AuthorityHandle {
        AuthorityHandle {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Serve until [`AuthorityHandle::shutdown`].
    pub async fn serve(self) -> Result<(), NetError> {
        let inner = Arc::clone(&self.inner);
        let span = info_span!("authority", name = %inner.config.name);
        async move {
            info!(
                listen = %self.local_addr(),
                network = %inner.config.network.name,
                approved = inner.config.approved.relays.len(),
                "authority started"
            );
            inner.sign_consensus();
            inner
                .tasks
                .spawn(Arc::clone(&inner).probe_loop().in_current_span());
            inner
                .tasks
                .spawn(Arc::clone(&inner).consensus_loop().in_current_span());
            loop {
                let accepted = tokio::select! {
                    accepted = self.listener.accept() => accepted,
                    _ = inner.shutdown.cancelled() => break,
                };
                let Ok((stream, peer)) = accepted else {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                };
                if !inner.config.network.scope.allows(peer) {
                    warn!(%peer, "refused connection from outside the network scope");
                    continue;
                }
                let Ok(permit) = Arc::clone(&inner.connections).try_acquire_owned() else {
                    warn!(%peer, "refused connection: too many connections");
                    continue;
                };
                let this = Arc::clone(&inner);
                inner.tasks.spawn(
                    async move {
                        if let Err(e) = this.serve_connection(stream).await {
                            debug!(%peer, error = %e, "directory connection ended");
                        }
                        drop(permit);
                    }
                    .in_current_span(),
                );
            }
            inner.tasks.close();
            let _ = tokio::time::timeout(Duration::from_secs(5), inner.tasks.wait()).await;
            info!("authority stopped");
            Ok(())
        }
        .instrument(span)
        .await
    }
}

impl AuthorityHandle {
    pub fn shutdown(&self) {
        self.inner.shutdown.cancel();
    }

    pub fn stats(&self) -> AuthorityStats {
        let relays = self.inner.relays.lock().unwrap();
        let c = &self.inner.counters;
        AuthorityStats {
            admitted_relays: relays.len(),
            running_relays: relays.values().filter(|r| r.running).count(),
            identity_changes_refused: c.identity_changes_refused.load(Ordering::Relaxed),
            unapproved_uploads: c.unapproved_uploads.load(Ordering::Relaxed),
            probes_ok: c.probes_ok.load(Ordering::Relaxed),
            probes_failed: c.probes_failed.load(Ordering::Relaxed),
            consensuses_signed: c.consensuses_signed.load(Ordering::Relaxed),
        }
    }

    /// Probe every relay and re-sign the consensus now (tests).
    pub async fn refresh_now(&self) {
        let ids: Vec<NodeId> = self.inner.relays.lock().unwrap().keys().copied().collect();
        for id in ids {
            Arc::clone(&self.inner).probe(id).await;
        }
        self.inner.sign_consensus();
    }
}

fn error(code: DirErrorCode, detail: impl Into<String>) -> DirResponse {
    DirResponse::Error {
        code,
        detail: detail.into(),
    }
}

impl Inner {
    async fn serve_connection(self: &Arc<Self>, stream: TcpStream) -> Result<(), NetError> {
        let accepted = Connection::accept(
            stream,
            self.keys.link_secret(),
            self.config.timeouts.handshake,
            |kind, _| {
                if kind == LinkKind::Directory {
                    Ok(())
                } else {
                    Err(format!(
                        "an authority only accepts directory links, not {kind:?}"
                    ))
                }
            },
        )
        .await?;
        let mut conn = accepted.conn;
        for _ in 0..MAX_REQUESTS_PER_CONNECTION {
            let bytes = tokio::select! {
                received = conn.recv_bytes(Duration::from_secs(30)) => received?,
                _ = self.shutdown.cancelled() => return Ok(()),
            };
            let Some(bytes) = bytes else { return Ok(()) };
            let response = match decode::<DirRequest>(&bytes) {
                Err(_) => error(DirErrorCode::BadRequest, "malformed request"),
                Ok(request) if request.version != DIR_PROTOCOL_VERSION => error(
                    DirErrorCode::VersionMismatch,
                    format!("directory protocol v{DIR_PROTOCOL_VERSION} required"),
                ),
                Ok(request) => self.handle(request.body),
            };
            conn.send_bytes(&encode(&response)).await?;
        }
        Ok(())
    }

    fn handle(self: &Arc<Self>, body: DirRequestBody) -> DirResponse {
        match body {
            DirRequestBody::PublishRelay { descriptor } => self.publish_relay(&descriptor),
            DirRequestBody::GetConsensus => match &*self.consensus.read().unwrap() {
                Some((document, _, _)) => DirResponse::Consensus {
                    document: document.clone(),
                },
                None => error(DirErrorCode::Unavailable, "no consensus yet"),
            },
            DirRequestBody::LookupService { id } => {
                let Ok(address) = MorpAddress::parse_id(&id) else {
                    return error(DirErrorCode::BadRequest, "invalid .morp id");
                };
                match self.services.lookup(&address) {
                    Ok(d) => DirResponse::Service {
                        descriptor: Some(d.to_json()),
                    },
                    Err((StoreError::NotFound, _)) => DirResponse::Service { descriptor: None },
                    Err((kind, detail)) => store_error(kind, detail),
                }
            }
            DirRequestBody::PublishService { id, descriptor } => {
                let Ok(address) = MorpAddress::parse_id(&id) else {
                    return error(DirErrorCode::BadRequest, "invalid .morp id");
                };
                match self.services.publish(&address, &descriptor) {
                    Ok(()) => DirResponse::Ok {
                        detail: "stored".into(),
                    },
                    Err((kind, detail)) => store_error(kind, detail),
                }
            }
            DirRequestBody::WithdrawService { id, withdrawal } => {
                let Ok(address) = MorpAddress::parse_id(&id) else {
                    return error(DirErrorCode::BadRequest, "invalid .morp id");
                };
                match self.services.withdraw(&address, &withdrawal) {
                    Ok(()) => DirResponse::Ok {
                        detail: "withdrawn".into(),
                    },
                    Err((kind, detail)) => store_error(kind, detail),
                }
            }
            DirRequestBody::Status => DirResponse::Status(self.status()),
        }
    }

    /// Admission rules for an uploaded relay descriptor.
    fn publish_relay(self: &Arc<Self>, bytes: &[u8]) -> DirResponse {
        let descriptor = match RelayDescriptor::from_wire(bytes) {
            Ok(d) => d,
            Err(e) => return error(DirErrorCode::Invalid, e.to_string()),
        };
        let Some(approved) = self.config.approved.by_nickname(&descriptor.nickname) else {
            self.counters
                .unapproved_uploads
                .fetch_add(1, Ordering::Relaxed);
            warn!(relay = %descriptor.nickname, identity = %descriptor.node_id, "upload from a relay that is not on the allowlist");
            return error(
                DirErrorCode::NotApproved,
                format!(
                    "{} is not on this authority's allowlist; ask the operator to add \
                     nickname = \"{}\", identity = \"{}\", role = \"{}\"",
                    descriptor.nickname, descriptor.nickname, descriptor.node_id, descriptor.role
                ),
            );
        };
        if approved.identity != descriptor.node_id {
            self.counters
                .identity_changes_refused
                .fetch_add(1, Ordering::Relaxed);
            warn!(
                relay = %descriptor.nickname,
                approved = %approved.identity.short(),
                offered = %descriptor.node_id.short(),
                "refused relay identity change"
            );
            return error(
                DirErrorCode::NotApproved,
                format!(
                    "identity change refused: {} is approved with identity {}, not {}",
                    descriptor.nickname, approved.identity, descriptor.node_id
                ),
            );
        }
        if approved.role != descriptor.role {
            return error(
                DirErrorCode::NotApproved,
                format!(
                    "{} is approved as a {} relay, not {}",
                    descriptor.nickname, approved.role, descriptor.role
                ),
            );
        }
        if let Err(e) = self.config.network.scope.check_reachable(descriptor.addr) {
            return error(DirErrorCode::Invalid, e.to_string());
        }
        let now = now_secs();
        if descriptor.published > now + super::consensus::CLOCK_SKEW
            || descriptor.published
                + self.config.relay_expiry.as_secs()
                + super::consensus::CLOCK_SKEW
                < now
        {
            return error(
                DirErrorCode::Invalid,
                "descriptor timestamp is too far from this authority's clock (check NTP)",
            );
        }

        let id = descriptor.node_id;
        let mut relays = self.relays.lock().unwrap();
        let new_keys = match relays.get_mut(&id) {
            Some(entry) if entry.descriptor.published > descriptor.published => {
                return error(
                    DirErrorCode::Conflict,
                    "a newer descriptor is already stored",
                );
            }
            Some(entry) if entry.descriptor == descriptor => {
                entry.uploaded = Instant::now();
                false
            }
            Some(entry) => {
                // Restart (new onion/link keys) or new address: probe again.
                let changed = entry.descriptor.link_key != descriptor.link_key
                    || entry.descriptor.addr != descriptor.addr;
                entry.descriptor = descriptor.clone();
                entry.uploaded = Instant::now();
                if changed {
                    entry.running = false;
                    entry.failures = 0;
                }
                true
            }
            None => {
                if relays.len() >= MAX_CONSENSUS_RELAYS {
                    return error(DirErrorCode::ResourceLimit, "too many relays");
                }
                info!(relay = %descriptor.nickname, addr = %descriptor.addr, "relay descriptor accepted; probing");
                relays.insert(
                    id,
                    RelayEntry {
                        descriptor: descriptor.clone(),
                        uploaded: Instant::now(),
                        last_probe: None,
                        running: false,
                        failures: 0,
                    },
                );
                true
            }
        };
        drop(relays);
        if new_keys {
            self.changed.notify_one();
            let this = Arc::clone(self);
            self.tasks
                .spawn(async move { this.probe(id).await }.in_current_span());
        }
        DirResponse::Ok {
            detail: "accepted; listed in the consensus once a health probe succeeds".into(),
        }
    }

    async fn probe_loop(self: Arc<Self>) {
        let mut tick = tokio::time::interval(self.config.probe_interval);
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = self.shutdown.cancelled() => return,
            }
            let expired: Vec<NodeId> = {
                let mut relays = self.relays.lock().unwrap();
                let expiry = self.config.relay_expiry;
                let gone: Vec<NodeId> = relays
                    .iter()
                    .filter(|(_, r)| r.uploaded.elapsed() > expiry)
                    .map(|(id, _)| *id)
                    .collect();
                for id in &gone {
                    if let Some(r) = relays.remove(id) {
                        info!(relay = %r.descriptor.nickname, "relay stopped uploading; removed");
                    }
                }
                gone
            };
            if !expired.is_empty() {
                self.changed.notify_one();
            }
            let ids: Vec<NodeId> = self.relays.lock().unwrap().keys().copied().collect();
            let probes = ids.into_iter().map(|id| Arc::clone(&self).probe(id));
            futures_util::future::join_all(probes).await;
        }
    }

    /// One health probe: a Noise `Probe` handshake proves the relay at the
    /// advertised address holds the descriptor's link key; its `Welcome`
    /// must name the approved role.
    async fn probe(self: Arc<Self>, id: NodeId) {
        let Some(descriptor) = self
            .relays
            .lock()
            .unwrap()
            .get(&id)
            .map(|r| r.descriptor.clone())
        else {
            return;
        };
        let result = async {
            let mut conn = Connection::connect_checked(
                descriptor.addr,
                LinkKind::Probe,
                &descriptor.link_key,
                None,
                &self.config.timeouts,
                &self.policy,
                "authority",
            )
            .await?;
            match conn.recv(self.config.timeouts.handshake).await? {
                Some(LinkMsg::Welcome { version, role })
                    if version == MORP_VERSION && role == descriptor.role =>
                {
                    Ok(())
                }
                other => Err(NetError::Protocol(format!(
                    "unexpected probe answer {other:?}"
                ))),
            }
        }
        .await;

        let mut relays = self.relays.lock().unwrap();
        let Some(entry) = relays.get_mut(&id) else {
            return;
        };
        if entry.descriptor.link_key != descriptor.link_key {
            return; // re-uploaded meanwhile; a new probe is on its way
        }
        entry.last_probe = Some(Instant::now());
        let was_running = entry.running;
        match result {
            Ok(()) => {
                self.counters.probes_ok.fetch_add(1, Ordering::Relaxed);
                entry.failures = 0;
                entry.running = true;
                if !was_running {
                    info!(relay = %descriptor.nickname, "relay reachable; listed in the consensus");
                }
            }
            Err(e) => {
                self.counters.probes_failed.fetch_add(1, Ordering::Relaxed);
                entry.failures += 1;
                if entry.failures >= MAX_PROBE_FAILURES {
                    entry.running = false;
                }
                warn!(relay = %descriptor.nickname, failures = entry.failures, error = %e, "health probe failed");
            }
        }
        if entry.running != was_running {
            drop(relays);
            self.changed.notify_one();
        }
    }

    async fn consensus_loop(self: Arc<Self>) {
        let mut tick = tokio::time::interval(self.config.consensus_interval);
        tick.tick().await;
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = self.changed.notified() => {
                    // Let a burst of changes settle.
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                _ = self.shutdown.cancelled() => return,
            }
            self.sign_consensus();
        }
    }

    fn sign_consensus(&self) {
        let mut relays: Vec<RelayDescriptor> = self
            .relays
            .lock()
            .unwrap()
            .values()
            .filter(|r| r.running)
            .map(|r| r.descriptor.clone())
            .collect();
        relays.sort_by(|a, b| a.nickname.cmp(&b.nickname));
        let now = now_secs();
        let previous = self.consensus.read().unwrap().as_ref().map(|(_, s, _)| *s);
        let sequence = previous
            .map(|p| p + 1)
            .unwrap_or(0)
            .max(crate::service::now_millis());
        let validity = Validity {
            sequence,
            valid_after: now,
            fresh_until: now + self.config.consensus_interval.as_secs(),
            valid_until: now + self.config.consensus_lifetime.as_secs(),
        };
        match SignedConsensus::sign(&self.keys, &self.config.network.name, validity, &relays) {
            Ok(doc) => {
                self.counters
                    .consensuses_signed
                    .fetch_add(1, Ordering::Relaxed);
                info!(sequence, relays = relays.len(), "consensus signed");
                *self.consensus.write().unwrap() =
                    Some((doc.to_bytes(), sequence, validity.valid_until));
            }
            Err(e) => warn!(error = %e, "could not sign consensus"),
        }
    }

    fn status(&self) -> AuthorityStatus {
        let relays = self.relays.lock().unwrap();
        let mut list: Vec<RelayStatus> = relays
            .values()
            .map(|r| RelayStatus {
                nickname: r.descriptor.nickname.clone(),
                role: r.descriptor.role,
                address: r.descriptor.addr,
                family: r.descriptor.family.clone(),
                running: r.running,
                consecutive_probe_failures: r.failures,
                seconds_since_upload: r.uploaded.elapsed().as_secs(),
                seconds_since_probe: r.last_probe.map(|t| t.elapsed().as_secs()),
            })
            .collect();
        list.sort_by(|a, b| a.nickname.cmp(&b.nickname));
        let consensus = self.consensus.read().unwrap();
        AuthorityStatus {
            name: self.config.name.clone(),
            network: self.config.network.name.clone(),
            consensus_sequence: consensus.as_ref().map(|(_, s, _)| *s),
            consensus_valid_until: consensus.as_ref().map(|(_, _, v)| *v),
            relays: list,
            identity_changes_refused: self
                .counters
                .identity_changes_refused
                .load(Ordering::Relaxed),
            unapproved_uploads: self.counters.unapproved_uploads.load(Ordering::Relaxed),
        }
    }
}

fn store_error(kind: StoreError, detail: String) -> DirResponse {
    let code = match kind {
        StoreError::BadRequest => DirErrorCode::BadRequest,
        StoreError::NotFound => DirErrorCode::NotFound,
        StoreError::Invalid => DirErrorCode::Invalid,
        StoreError::Conflict => DirErrorCode::Conflict,
        StoreError::Full => DirErrorCode::ResourceLimit,
    };
    error(code, detail)
}
