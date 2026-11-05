//! Hidden-service host.
//!
//! 1. Build an outgoing circuit to each introduction point (a
//!    rendezvous-role relay) and register a fresh per-intro auth key there.
//! 2. Publish a descriptor listing the intro points (no location).
//! 3. For each `Introduce2`: decrypt it, reject replays, build a *new*
//!    outgoing circuit to the client's chosen rendezvous point, send
//!    `Rendezvous1`, and serve the end-to-end session by forwarding requests
//!    to the local web application.
//!
//! The service never accepts inbound connections for MORP traffic; its only
//! listening socket is the local application on 127.0.0.1.
//!
//! When an introduction circuit is lost (a relay or machine went away),
//! [`HiddenService::replenish`] establishes a replacement at another
//! rendezvous-role relay; the caller then republishes the descriptor.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{Notify, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::app::AppForwarder;
use super::crypto::{IntroKeys, Introduction, accept_introduction, open_introduction};
use super::session::{self, Handler, HttpRequest};
use crate::NetError;
use crate::address::MorpAddress;
use crate::client::{Circuit, build_circuit_to};
use crate::identity::{NodeId, Role};
use crate::limits::{Rate, TokenBucket};
use crate::protocol::RelayCmd;
use crate::service::descriptor::{IntroPoint, MAX_INTRO_POINTS, ServiceDescriptor};
use crate::service::keys::ServiceKeys;
use crate::transport::{ConnectPolicy, Timeouts};
use crate::trust::TrustedRelays;

#[derive(Clone, Debug)]
pub struct HostConfig {
    /// Where relays come from: a local folder or a signed consensus.
    pub relays: TrustedRelays,
    /// The local web application (loopback only).
    pub app: SocketAddr,
    pub intro_points: usize,
    pub timeouts: Timeouts,
    pub policy: ConnectPolicy,
    pub max_sessions: usize,
    /// Timeout for each request to the local application.
    pub app_timeout: Duration,
    /// Introductions accepted through one introduction point before it is
    /// replaced by a fresh one (new keys, possibly another relay). Each
    /// intro point remembers the introductions it accepted to reject
    /// replays; rotating bounds that memory without ever forgetting a
    /// replay that could still arrive (Tor rotates intro points the same way).
    pub max_introductions_per_intro: usize,
    /// Introductions processed, over all intro points. Each costs the
    /// service a new circuit to a rendezvous point chosen by the client.
    pub introduction_rate: Rate,
    /// Rendezvous circuits being built at once.
    pub max_pending_rendezvous: usize,
}

impl HostConfig {
    /// `relays`: a [`TrustedRelays`], or a folder path (local mode).
    pub fn new(relays: impl Into<TrustedRelays>, app: SocketAddr) -> Self {
        Self {
            relays: relays.into(),
            app,
            intro_points: 2,
            timeouts: Timeouts::default(),
            policy: ConnectPolicy::allow_all(),
            max_sessions: 64,
            app_timeout: Duration::from_secs(30),
            max_introductions_per_intro: 16_384,
            introduction_rate: Rate::new(10.0, 64),
            max_pending_rendezvous: 16,
        }
    }
}

/// Counters for tests and diagnostics.
#[derive(Debug, Default)]
pub struct HostStats {
    pub introductions: AtomicU64,
    pub bad_introductions: AtomicU64,
    pub replays_rejected: AtomicU64,
    pub sessions_started: AtomicU64,
    pub active_sessions: AtomicUsize,
    pub requests: AtomicU64,
    pub live_intro_points: AtomicUsize,
    /// Introduction points re-established after one was lost.
    pub intro_points_replaced: AtomicU64,
    /// Introduction points retired after `max_introductions_per_intro`.
    pub intro_points_rotated: AtomicU64,
    /// Introductions dropped by the service's introduction rate limit.
    pub introductions_rate_limited: AtomicU64,
    /// Introductions dropped because too many rendezvous circuits were
    /// already being built, or the session limit was reached.
    pub introductions_dropped: AtomicU64,
}

struct Ctx {
    identity: Arc<ServiceKeys>,
    config: HostConfig,
    forwarder: Arc<AppForwarder>,
    stats: Arc<HostStats>,
    intro_limiter: Mutex<TokenBucket>,
    pending_rendezvous: Arc<Semaphore>,
    sessions: Arc<Semaphore>,
    shutdown: CancellationToken,
    /// Live introduction points (what the descriptor should list).
    intros: Mutex<Vec<IntroPoint>>,
    wanted: usize,
    /// Fires when an introduction point is lost.
    intro_lost: Notify,
}

/// A running hidden service.
pub struct HiddenService {
    ctx: Arc<Ctx>,
}

impl HiddenService {
    /// Establish introduction points and start listening for introductions.
    /// Publishing the descriptor is up to the caller (see [`descriptor`]).
    ///
    /// [`descriptor`]: HiddenService::descriptor
    pub async fn start(identity: ServiceKeys, mut config: HostConfig) -> Result<Self, NetError> {
        let wanted = config.intro_points.clamp(1, MAX_INTRO_POINTS);
        config.policy = config.policy.with_scope(config.relays.scope());
        let forwarder = Arc::new(AppForwarder::new(
            config.app,
            config.policy.clone(),
            config.app_timeout,
        )?);
        config.relays.snapshot()?;

        let ctx = Arc::new(Ctx {
            identity: Arc::new(identity),
            forwarder,
            stats: Arc::default(),
            intro_limiter: Mutex::new(TokenBucket::new(config.introduction_rate)),
            pending_rendezvous: Arc::new(Semaphore::new(config.max_pending_rendezvous.max(1))),
            sessions: Arc::new(Semaphore::new(config.max_sessions)),
            shutdown: CancellationToken::new(),
            config,
            intros: Mutex::new(Vec::new()),
            wanted,
            intro_lost: Notify::new(),
        });
        let service = Self { ctx };
        if let Err(e) = service.replenish().await
            && service.ctx.intros.lock().unwrap().is_empty()
        {
            service.ctx.shutdown.cancel();
            return Err(e);
        }
        Ok(service)
    }

    /// Establish introduction points until the configured number are live.
    /// Returns how many were added; the caller should republish the
    /// descriptor if that is more than zero. Errors only if none could be
    /// added while some were missing.
    pub async fn replenish(&self) -> Result<usize, NetError> {
        let ctx = &self.ctx;
        let mut added = 0;
        let mut tried: Vec<NodeId> = Vec::new();
        let mut last_error = None;
        loop {
            let current: Vec<NodeId> = ctx
                .intros
                .lock()
                .unwrap()
                .iter()
                .map(|ip| ip.relay)
                .collect();
            if current.len() >= ctx.wanted || ctx.shutdown.is_cancelled() {
                break;
            }
            let keys = IntroKeys::generate();
            let avoid: Vec<NodeId> = current.iter().chain(&tried).copied().collect();
            let attempt = establish_intro(ctx, &avoid, &keys).await;
            match attempt {
                Ok((circuit, relay, nickname)) => {
                    info!(intro = %nickname, "introduction point established");
                    ctx.intros.lock().unwrap().push(IntroPoint {
                        relay,
                        auth_key: keys.auth_public(),
                        enc_key: keys.enc_public(),
                    });
                    ctx.stats.live_intro_points.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(intro_listener(
                        Arc::clone(ctx),
                        circuit,
                        Arc::new(keys),
                        relay,
                    ));
                    added += 1;
                    tried.push(relay);
                }
                Err((e, relay)) => {
                    warn!(error = %e, "introduction point failed");
                    last_error = Some(e);
                    match relay {
                        Some(relay) if !tried.contains(&relay) => tried.push(relay),
                        _ => break, // no untried rendezvous-role relay left
                    }
                }
            }
        }
        if added == 0
            && let Some(e) = last_error
        {
            return Err(e);
        }
        Ok(added)
    }

    /// Resolves when an introduction point is lost.
    pub async fn intro_point_lost(&self) {
        self.ctx.intro_lost.notified().await;
    }

    /// Number of live introduction points.
    pub fn live_intro_points(&self) -> usize {
        self.ctx.intros.lock().unwrap().len()
    }

    /// How many introduction points this service tries to keep.
    pub fn wanted_intro_points(&self) -> usize {
        self.ctx.wanted
    }

    pub fn address(&self) -> &MorpAddress {
        self.ctx.identity.address()
    }

    /// The live introduction points.
    pub fn intro_points(&self) -> Vec<IntroPoint> {
        self.ctx.intros.lock().unwrap().clone()
    }

    /// A signed descriptor listing this service's live introduction points.
    pub fn descriptor(&self, now: u64, lifetime: u64, revision: u64) -> ServiceDescriptor {
        ServiceDescriptor::sign(
            &self.ctx.identity,
            self.intro_points(),
            now,
            lifetime,
            revision,
        )
    }

    pub fn identity(&self) -> Arc<ServiceKeys> {
        Arc::clone(&self.ctx.identity)
    }

    pub fn stats(&self) -> Arc<HostStats> {
        Arc::clone(&self.ctx.stats)
    }

    /// Close intro circuits and all sessions.
    pub fn shutdown(&self) {
        self.ctx.shutdown.cancel();
    }
}

impl Drop for HiddenService {
    fn drop(&mut self) {
        self.ctx.shutdown.cancel();
    }
}

/// Build a circuit to an unused rendezvous-role relay and register `keys`
/// there. On failure, also returns the relay that was tried (if any).
async fn establish_intro(
    ctx: &Ctx,
    avoid: &[NodeId],
    keys: &IntroKeys,
) -> Result<(Circuit, NodeId, String), (NetError, Option<NodeId>)> {
    let directory = ctx.config.relays.snapshot().map_err(|e| (e, None))?;
    let available = directory
        .relays()
        .iter()
        .any(|d| d.role == Role::Rendezvous && !avoid.contains(&d.node_id));
    if !available {
        return Err((
            NetError::InvalidConfig(
                "no unused rendezvous-role relay in the relay directory".into(),
            ),
            None,
        ));
    }
    let chosen = Mutex::new(None);
    let built = build_circuit_to(
        &ctx.config.relays,
        |directory, unhealthy| {
            let pick = directory
                .pick(Role::Rendezvous, avoid, &[], unhealthy)
                .filter(|d| !avoid.contains(&d.node_id));
            *chosen.lock().unwrap() = pick.as_ref().map(|d| d.node_id);
            pick
        },
        ctx.config.timeouts,
        &ctx.config.policy,
        "service",
        3,
    )
    .await;
    let relay_tried = *chosen.lock().unwrap();
    let (_link, mut circuit, path) = built.map_err(|e| (e, relay_tried))?;
    let relay = path.last;
    let reply = circuit
        .request(
            RelayCmd::EstablishIntro {
                auth_key: keys.auth_public(),
                signature: keys.establish_signature(&relay.node_id),
            },
            ctx.config.timeouts.handshake,
        )
        .await
        .map_err(|e| (e, Some(relay.node_id)))?;
    match reply {
        RelayCmd::IntroEstablished => Ok((circuit, relay.node_id, relay.nickname)),
        _ => Err((
            NetError::Protocol("expected IntroEstablished".into()),
            Some(relay.node_id),
        )),
    }
}

/// Receive introductions on one intro circuit. Introductions are decrypted
/// and checked for replay here, one at a time; only good ones start a
/// rendezvous. Each intro point has its own replay cache: once it has
/// accepted `max_introductions_per_intro` introductions the intro point is
/// retired (and replaced with fresh keys), so the cache never has to forget
/// an entry while a replay of it could still be delivered.
///
/// Regression (v0.7): there used to be one service-wide cache that, once
/// full, refused *all* introductions until the service restarted; anyone
/// could fill it with valid introductions and take the service offline.
async fn intro_listener(ctx: Arc<Ctx>, mut circuit: Circuit, keys: Arc<IntroKeys>, relay: NodeId) {
    let address = *ctx.identity.address();
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut rotate = false;
    loop {
        let received = tokio::select! {
            received = circuit.recv_from_last(None) => received,
            _ = ctx.shutdown.cancelled() => break,
        };
        match received {
            Ok(RelayCmd::Introduce2 { payload }) => {
                ctx.stats.introductions.fetch_add(1, Ordering::Relaxed);
                if !ctx.intro_limiter.lock().unwrap().try_take() {
                    ctx.stats
                        .introductions_rate_limited
                        .fetch_add(1, Ordering::Relaxed);
                    warn!("introduction rate limit reached; dropping an introduction");
                    continue;
                }
                let intro = match open_introduction(&address, &keys, &payload) {
                    Ok(intro) => intro,
                    Err(e) => {
                        ctx.stats.bad_introductions.fetch_add(1, Ordering::Relaxed);
                        warn!(error = %e, "rejected undecryptable introduction");
                        continue;
                    }
                };
                if !seen.insert(intro.client_ephemeral) {
                    ctx.stats.replays_rejected.fetch_add(1, Ordering::Relaxed);
                    warn!("rejected replayed introduction");
                    continue;
                }
                tokio::spawn(handle_introduction(Arc::clone(&ctx), intro));
                if seen.len() >= ctx.config.max_introductions_per_intro {
                    info!(
                        introductions = seen.len(),
                        "introduction point reached its limit; rotating to fresh keys"
                    );
                    rotate = true;
                    break;
                }
            }
            Ok(other) => debug!(
                cmd = other.kind(),
                "ignoring unexpected command on intro circuit"
            ),
            Err(e) => {
                warn!(error = %e, "introduction circuit lost");
                break;
            }
        }
    }
    drop(circuit); // destroys the intro registration at the relay
    let auth = keys.auth_public();
    ctx.intros.lock().unwrap().retain(|ip| ip.auth_key != auth);
    ctx.stats.live_intro_points.fetch_sub(1, Ordering::SeqCst);
    if !ctx.shutdown.is_cancelled() {
        if rotate {
            ctx.stats
                .intro_points_rotated
                .fetch_add(1, Ordering::Relaxed);
        } else {
            ctx.config
                .relays
                .health()
                .mark_failed(relay, crate::trust::DEFAULT_PENALTY);
        }
        ctx.intro_lost.notify_one();
    }
}

async fn handle_introduction(ctx: Arc<Ctx>, intro: Introduction) {
    let Ok(permit) = Arc::clone(&ctx.sessions).try_acquire_owned() else {
        ctx.stats
            .introductions_dropped
            .fetch_add(1, Ordering::Relaxed);
        warn!("session limit reached; ignoring introduction");
        return;
    };
    let Ok(pending) = Arc::clone(&ctx.pending_rendezvous).try_acquire_owned() else {
        ctx.stats
            .introductions_dropped
            .fetch_add(1, Ordering::Relaxed);
        warn!("too many rendezvous circuits being built; ignoring introduction");
        return;
    };

    let setup = async {
        let rendezvous = ctx
            .config
            .relays
            .find(&intro.rendezvous)
            .filter(|d| d.role == Role::Rendezvous)
            .ok_or_else(|| {
                NetError::InvalidConfig("client asked for an unknown rendezvous relay".into())
            })?;
        // The service's own, separate circuit to the client's rendezvous
        // point (fresh entry and middle; retried on another path if needed).
        let (_link, mut circuit, _path) = build_circuit_to(
            &ctx.config.relays,
            |_, _| Some(rendezvous.clone()),
            ctx.config.timeouts,
            &ctx.config.policy,
            "service",
            3,
        )
        .await?;
        let (reply, session_keys) = accept_introduction(&ctx.identity, &intro)?;
        circuit
            .send_to_last(RelayCmd::Rendezvous1 {
                cookie: intro.cookie,
                payload: reply,
            })
            .await?;
        Ok::<_, NetError>((circuit, session_keys, rendezvous.nickname))
    };
    let (circuit, session_keys, rendezvous) =
        match tokio::time::timeout(ctx.config.timeouts.handshake * 4, setup).await {
            Ok(Ok(ok)) => ok,
            Ok(Err(e)) => {
                warn!(error = %e, "could not reach the rendezvous point");
                return;
            }
            Err(_) => {
                warn!("timed out reaching the rendezvous point");
                return;
            }
        };
    drop(pending);

    info!(%rendezvous, "rendezvous complete; serving session");
    ctx.stats.sessions_started.fetch_add(1, Ordering::Relaxed);
    ctx.stats.active_sessions.fetch_add(1, Ordering::SeqCst);

    let forwarder = Arc::clone(&ctx.forwarder);
    let stats = Arc::clone(&ctx.stats);
    let handler: Handler = Arc::new(move |request: HttpRequest| {
        let forwarder = Arc::clone(&forwarder);
        stats.requests.fetch_add(1, Ordering::Relaxed);
        Box::pin(async move { forwarder.forward(request).await })
    });

    let pipe = circuit.into_stream_pipe();
    let reason = tokio::select! {
        reason = session::serve(pipe, session_keys, handler) => reason,
        _ = ctx.shutdown.cancelled() => "service shutting down".to_owned(),
    };
    info!(%reason, "session ended");
    ctx.stats.active_sessions.fetch_sub(1, Ordering::SeqCst);
    drop(permit);
}
