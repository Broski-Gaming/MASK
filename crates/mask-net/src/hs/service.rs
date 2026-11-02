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

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::app::AppForwarder;
use super::crypto::{IntroKeys, accept_introduction, open_introduction};
use super::session::{self, Handler, HttpRequest};
use crate::NetError;
use crate::address::MorpAddress;
use crate::client::{Circuit, ClientLink};
use crate::descriptor::Directory;
use crate::identity::Role;
use crate::protocol::RelayCmd;
use crate::service::descriptor::{IntroPoint, MAX_INTRO_POINTS, ServiceDescriptor};
use crate::service::keys::ServiceKeys;
use crate::transport::{ConnectPolicy, Timeouts};

/// Remembered client ephemeral keys (replay protection), per service run.
const MAX_SEEN_INTRODUCTIONS: usize = 100_000;

#[derive(Clone, Debug)]
pub struct HostConfig {
    /// Folder of relay descriptors.
    pub relay_directory: PathBuf,
    /// The local web application (loopback only).
    pub app: SocketAddr,
    pub intro_points: usize,
    pub timeouts: Timeouts,
    pub policy: ConnectPolicy,
    pub max_sessions: usize,
    /// Timeout for each request to the local application.
    pub app_timeout: Duration,
}

impl HostConfig {
    pub fn new(relay_directory: PathBuf, app: SocketAddr) -> Self {
        Self {
            relay_directory,
            app,
            intro_points: 2,
            timeouts: Timeouts::default(),
            policy: ConnectPolicy::allow_all(),
            max_sessions: 64,
            app_timeout: Duration::from_secs(30),
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
}

struct Ctx {
    identity: Arc<ServiceKeys>,
    config: HostConfig,
    forwarder: Arc<AppForwarder>,
    stats: Arc<HostStats>,
    seen: Mutex<HashSet<[u8; 32]>>,
    sessions: Arc<Semaphore>,
    shutdown: CancellationToken,
}

/// A running hidden service.
pub struct HiddenService {
    ctx: Arc<Ctx>,
    intro_points: Vec<IntroPoint>,
}

impl HiddenService {
    /// Establish introduction points and start listening for introductions.
    /// Publishing the descriptor is up to the caller (see [`descriptor`]).
    ///
    /// [`descriptor`]: HiddenService::descriptor
    pub async fn start(identity: ServiceKeys, config: HostConfig) -> Result<Self, NetError> {
        let wanted = config.intro_points.clamp(1, MAX_INTRO_POINTS);
        let forwarder = Arc::new(AppForwarder::new(
            config.app,
            config.policy.clone(),
            config.app_timeout,
        )?);
        let (relays, _) = Directory::load(&config.relay_directory)?;

        let ctx = Arc::new(Ctx {
            identity: Arc::new(identity),
            forwarder,
            stats: Arc::default(),
            seen: Mutex::new(HashSet::new()),
            sessions: Arc::new(Semaphore::new(config.max_sessions)),
            shutdown: CancellationToken::new(),
            config,
        });

        let mut intro_points = Vec::new();
        let mut used = Vec::new();
        let mut last_error = None;
        while intro_points.len() < wanted {
            let Some(relay) = relays.random_relay(Role::Rendezvous, &used) else {
                break;
            };
            if used.contains(&relay.node_id) {
                break; // no unused rendezvous-role relays left
            }
            used.push(relay.node_id);
            let keys = IntroKeys::generate();
            match establish_intro(&ctx, &relays, &relay, &keys).await {
                Ok(circuit) => {
                    info!(intro = %relay.nickname, "introduction point established");
                    intro_points.push(IntroPoint {
                        relay: relay.node_id,
                        auth_key: keys.auth_public(),
                        enc_key: keys.enc_public(),
                    });
                    ctx.stats.live_intro_points.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(intro_listener(Arc::clone(&ctx), circuit, Arc::new(keys)));
                }
                Err(e) => {
                    warn!(intro = %relay.nickname, error = %e, "introduction point failed");
                    last_error = Some(e);
                }
            }
        }
        if intro_points.is_empty() {
            ctx.shutdown.cancel();
            return Err(last_error.unwrap_or_else(|| {
                NetError::InvalidConfig("no rendezvous-role relays in the relay directory".into())
            }));
        }
        Ok(Self { ctx, intro_points })
    }

    pub fn address(&self) -> &MorpAddress {
        self.ctx.identity.address()
    }

    pub fn intro_points(&self) -> &[IntroPoint] {
        &self.intro_points
    }

    /// A signed descriptor listing this service's introduction points.
    pub fn descriptor(&self, now: u64, lifetime: u64, revision: u64) -> ServiceDescriptor {
        ServiceDescriptor::sign(
            &self.ctx.identity,
            self.intro_points.clone(),
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

async fn establish_intro(
    ctx: &Ctx,
    relays: &Directory,
    relay: &crate::descriptor::RelayDescriptor,
    keys: &IntroKeys,
) -> Result<Circuit, NetError> {
    let path = relays.path_ending_at(relay)?;
    let link = ClientLink::connect_with(
        &path.entry,
        ctx.config.timeouts,
        &ctx.config.policy,
        "service",
    )
    .await?;
    let mut circuit = link.build_circuit(&path).await?;
    let reply = circuit
        .request(
            RelayCmd::EstablishIntro {
                auth_key: keys.auth_public(),
                signature: keys.establish_signature(&relay.node_id),
            },
            ctx.config.timeouts.handshake,
        )
        .await?;
    match reply {
        RelayCmd::IntroEstablished => Ok(circuit),
        _ => Err(NetError::Protocol("expected IntroEstablished".into())),
    }
}

async fn intro_listener(ctx: Arc<Ctx>, mut circuit: Circuit, keys: Arc<IntroKeys>) {
    loop {
        let received = tokio::select! {
            received = circuit.recv_from_last(None) => received,
            _ = ctx.shutdown.cancelled() => break,
        };
        match received {
            Ok(RelayCmd::Introduce2 { payload }) => {
                ctx.stats.introductions.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(handle_introduction(
                    Arc::clone(&ctx),
                    Arc::clone(&keys),
                    payload,
                ));
            }
            Ok(other) => debug!(?other, "ignoring unexpected command on intro circuit"),
            Err(e) => {
                warn!(error = %e, "introduction circuit lost");
                break;
            }
        }
    }
    ctx.stats.live_intro_points.fetch_sub(1, Ordering::SeqCst);
}

async fn handle_introduction(ctx: Arc<Ctx>, keys: Arc<IntroKeys>, payload: Vec<u8>) {
    let address = *ctx.identity.address();
    let intro = match open_introduction(&address, &keys, &payload) {
        Ok(intro) => intro,
        Err(e) => {
            ctx.stats.bad_introductions.fetch_add(1, Ordering::Relaxed);
            warn!(error = %e, "rejected undecryptable introduction");
            return;
        }
    };
    {
        let mut seen = ctx.seen.lock().unwrap();
        if seen.contains(&intro.client_ephemeral) {
            ctx.stats.replays_rejected.fetch_add(1, Ordering::Relaxed);
            warn!("rejected replayed introduction");
            return;
        }
        if seen.len() >= MAX_SEEN_INTRODUCTIONS {
            warn!("replay cache full; refusing introductions until restart");
            return;
        }
        seen.insert(intro.client_ephemeral);
    }
    let Ok(permit) = Arc::clone(&ctx.sessions).try_acquire_owned() else {
        warn!("session limit reached; ignoring introduction");
        return;
    };

    let setup = async {
        let (relays, _) = Directory::load(&ctx.config.relay_directory)?;
        let rendezvous = relays
            .find(&intro.rendezvous)
            .filter(|d| d.role == Role::Rendezvous)
            .cloned()
            .ok_or_else(|| {
                NetError::InvalidConfig("client asked for an unknown rendezvous relay".into())
            })?;
        let path = relays.path_ending_at(&rendezvous)?;
        let link = ClientLink::connect_with(
            &path.entry,
            ctx.config.timeouts,
            &ctx.config.policy,
            "service",
        )
        .await?;
        let mut circuit = link.build_circuit(&path).await?;
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
