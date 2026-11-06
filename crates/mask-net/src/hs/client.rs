//! Hidden-service client: reach a `.morp` service through MORP relays only.
//!
//! 1. Look up and verify the service descriptor (introduction points).
//! 2. Pick a rendezvous point (rendezvous-role relay) and build a circuit
//!    to it: entry → middle → rendezvous. Register a random single-use cookie.
//! 3. Build a circuit to one of the service's intro points and send
//!    `Introduce1`, encrypted to the service, naming the rendezvous point and
//!    cookie.
//! 4. Wait for `Rendezvous2` on the rendezvous circuit, verify the service's
//!    signature against the `.morp` address, and derive session keys.
//! 5. Exchange end-to-end encrypted requests over the joined circuits.
//!
//! There is no other way to reach a service: no direct connection, no DNS,
//! no fallback. Sessions are reused for later requests to the same address.
//!
//! In network mode (v0.6) relays come from the signed consensus, refreshed
//! from the directory authorities when stale, and descriptors are looked up
//! at the authorities over Noise links. Relays that fail are avoided for a
//! while and the rendezvous circuit is retried on a fresh path.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tracing::{info, warn};

use super::crypto::ClientIntro;
use super::session::{ClientSession, HttpRequest, HttpResponse, SessionError};
use crate::NetError;
use crate::address::MorpAddress;
use crate::client::build_circuit_to;
use crate::crypto::random_bytes;
use crate::directory::ServiceDirectory;
use crate::directory::client::LookupError;
use crate::guards::{GuardConfig, Guards};
use crate::identity::Role;
use crate::protocol::{ErrorCode, RelayCmd};
use crate::transport::{ConnectPolicy, Timeouts};
use crate::trust::TrustedRelays;

/// Most cached sessions (one per address).
const MAX_SESSIONS: usize = 32;

type SessionSlot = Arc<tokio::sync::Mutex<Option<ClientSession>>>;

#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// Where relays come from: a local folder or a signed consensus.
    pub relays: TrustedRelays,
    pub timeouts: Timeouts,
    pub policy: ConnectPolicy,
    /// Time allowed for the whole connection setup.
    pub connect_timeout: Duration,
    /// Time allowed for the service to arrive at the rendezvous point.
    pub rendezvous_timeout: Duration,
    pub request_timeout: Duration,
    /// This client's entry guards (v0.7). In memory by default; the
    /// browser and the CLI use [`Guards::persistent`].
    pub guards: Guards,
}

impl ClientConfig {
    /// `relays`: a [`TrustedRelays`], or a folder path (local mode).
    pub fn new(relays: impl Into<TrustedRelays>) -> Self {
        Self {
            relays: relays.into(),
            timeouts: Timeouts::default(),
            policy: ConnectPolicy::allow_all(),
            connect_timeout: Duration::from_secs(45),
            rendezvous_timeout: Duration::from_secs(20),
            request_timeout: Duration::from_secs(30),
            guards: Guards::ephemeral(GuardConfig::default()),
        }
    }
}

#[derive(Debug)]
pub enum FetchError {
    DirectoryUnavailable(String),
    /// No valid, unexpired descriptor for the address.
    NotFound,
    DescriptorInvalid(String),
    /// The relay directory is missing or lacks needed relays.
    RelaysUnavailable(String),
    /// A relay circuit could not be built or failed.
    CircuitFailed(String),
    /// The service's intro points or rendezvous did not work out.
    ServiceUnavailable(String),
    /// The service could not prove it owns the address.
    IdentityMismatch(String),
    Timeout,
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DirectoryUnavailable(why) => write!(f, "MORP directory unavailable: {why}"),
            Self::NotFound => write!(f, "no service is currently published at this address"),
            Self::DescriptorInvalid(why) => write!(f, "invalid service descriptor: {why}"),
            Self::RelaysUnavailable(why) => write!(f, "MORP relays unavailable: {why}"),
            Self::CircuitFailed(why) => write!(f, "relay circuit failed: {why}"),
            Self::ServiceUnavailable(why) => write!(f, "service is not reachable: {why}"),
            Self::IdentityMismatch(why) => write!(
                f,
                "the service could not prove it owns this .morp address: {why}"
            ),
            Self::Timeout => write!(f, "timed out"),
        }
    }
}

impl std::error::Error for FetchError {}

/// The relays a session went through (nicknames), for display and tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRoute {
    pub entry: String,
    pub middle: String,
    pub rendezvous: String,
    pub intro_point: String,
}

/// Fetches pages from `.morp` services over relay circuits.
#[derive(Clone)]
pub struct MorpClient {
    directory: ServiceDirectory,
    config: Arc<ClientConfig>,
    sessions: Arc<Mutex<HashMap<MorpAddress, SessionSlot>>>,
}

impl MorpClient {
    /// `directory`: the local HTTP directory or the network's authorities.
    /// The connection policy is confined to the relays' network scope.
    pub fn new(directory: impl Into<ServiceDirectory>, mut config: ClientConfig) -> Self {
        config.policy = config.policy.with_scope(config.relays.scope());
        Self {
            directory: directory.into(),
            config: Arc::new(config),
            sessions: Arc::default(),
        }
    }

    /// Fetch `request` from the service at `address`, reusing an open
    /// session when there is one.
    pub async fn fetch(
        &self,
        address: &MorpAddress,
        request: HttpRequest,
    ) -> Result<HttpResponse, FetchError> {
        let session = self.session(address).await?;
        session
            .request(request, self.config.request_timeout)
            .await
            .map_err(|e| match e {
                SessionError::Timeout => FetchError::Timeout,
                other => FetchError::CircuitFailed(other.to_string()),
            })
    }

    /// Drop all cached sessions, closing their circuits.
    pub fn close_all(&self) {
        self.sessions.lock().unwrap().clear();
    }

    async fn session(&self, address: &MorpAddress) -> Result<ClientSession, FetchError> {
        let slot = {
            let mut sessions = self.sessions.lock().unwrap();
            if sessions.len() >= MAX_SESSIONS && !sessions.contains_key(address) {
                sessions.retain(|_, slot| {
                    slot.try_lock()
                        .map(|s| s.as_ref().is_some_and(ClientSession::is_open))
                        .unwrap_or(true)
                });
                if sessions.len() >= MAX_SESSIONS {
                    let victim = *sessions.keys().next().expect("non-empty");
                    sessions.remove(&victim);
                }
            }
            Arc::clone(sessions.entry(*address).or_default())
        };
        let mut guard = slot.lock().await;
        if let Some(session) = guard.as_ref()
            && session.is_open()
        {
            return Ok(session.clone());
        }
        let (session, _) = self.connect(address).await?;
        *guard = Some(session.clone());
        Ok(session)
    }

    /// Build a fresh session (does not touch the cache).
    pub async fn connect(
        &self,
        address: &MorpAddress,
    ) -> Result<(ClientSession, SessionRoute), FetchError> {
        tokio::time::timeout(self.config.connect_timeout, self.connect_inner(address))
            .await
            .map_err(|_| FetchError::Timeout)?
    }

    async fn connect_inner(
        &self,
        address: &MorpAddress,
    ) -> Result<(ClientSession, SessionRoute), FetchError> {
        let config = &self.config;

        // 1. Descriptor.
        let descriptor = match self.directory.lookup(address).await {
            Ok(Some(d)) => d,
            Ok(None) => return Err(FetchError::NotFound),
            Err(LookupError::Unavailable(why)) => {
                return Err(FetchError::DirectoryUnavailable(why));
            }
            Err(LookupError::Invalid(why)) => return Err(FetchError::DescriptorInvalid(why)),
        };

        // 2. Rendezvous circuit: a random rendezvous-role relay that is not
        // one of the service's intro points, on a fresh path, with retries.
        if let Some(authorities) = self.directory.authorities() {
            authorities
                .refresh_if_needed(&config.relays)
                .await
                .map_err(|e| FetchError::RelaysUnavailable(e.to_string()))?;
        }
        let relays = config
            .relays
            .snapshot()
            .map_err(|e| FetchError::RelaysUnavailable(e.to_string()))?;
        let intro_relays: Vec<_> = descriptor.intro_points.iter().map(|ip| ip.relay).collect();
        if !relays.relays().iter().any(|d| d.role == Role::Rendezvous) {
            return Err(FetchError::RelaysUnavailable(
                "no rendezvous-role relay".into(),
            ));
        }
        let circuit_err = |stage: &str| {
            let stage = stage.to_owned();
            move |e: NetError| FetchError::CircuitFailed(format!("{stage}: {e}"))
        };
        let (link, mut rp_circuit, rp_path) = build_circuit_to(
            &config.relays,
            &config.guards,
            |directory, hints| {
                // Never a relay known to be failing (if any other exists);
                // preferably unrelated to our guard and not one of the
                // service's intro points.
                let guard = hints.unrelated_to();
                directory
                    .pick_unrelated(Role::Rendezvous, hints.unhealthy, &guard, &intro_relays)
                    .or_else(|| {
                        directory.pick_unrelated(Role::Rendezvous, &[], &guard, &intro_relays)
                    })
            },
            config.timeouts,
            &config.policy,
            "client",
            3,
        )
        .await
        .map_err(circuit_err("building rendezvous circuit"))?;
        let rendezvous = rp_path.last.clone();
        let cookie: [u8; 32] = random_bytes();
        match rp_circuit
            .request(
                RelayCmd::EstablishRendezvous { cookie },
                config.timeouts.handshake,
            )
            .await
            .map_err(circuit_err("establishing rendezvous"))?
        {
            RelayCmd::RendezvousEstablished => {}
            _ => {
                return Err(FetchError::CircuitFailed(
                    "unexpected rendezvous reply".into(),
                ));
            }
        }

        // 3. Introduction, trying each intro point in turn.
        let mut introduced = None;
        let mut problems = Vec::new();
        for ip in &descriptor.intro_points {
            let Some(intro_relay) = config.relays.find(&ip.relay) else {
                problems.push("intro relay not in relay directory".to_owned());
                continue;
            };
            let attempt = async {
                // Reuse our link to the guard when it may be used with this
                // intro point; otherwise a separate circuit through another
                // (unrelated) guard, or none at all.
                let mut circuit = if rp_path.entry.related_to(&intro_relay) {
                    build_circuit_to(
                        &config.relays,
                        &config.guards,
                        |_, _| Some(intro_relay.clone()),
                        config.timeouts,
                        &config.policy,
                        "client",
                        2,
                    )
                    .await?
                    .1
                } else {
                    let unhealthy = config.relays.health().unhealthy();
                    let path = relays.path_through(&rp_path.entry, &intro_relay, &unhealthy)?;
                    link.build_circuit(&path).await?
                };
                let (client_intro, payload) = ClientIntro::new(
                    *address,
                    &ip.auth_key,
                    &ip.enc_key,
                    rendezvous.node_id,
                    cookie,
                )?;
                let reply = circuit
                    .request(
                        RelayCmd::Introduce1 {
                            auth_key: ip.auth_key,
                            payload,
                        },
                        config.timeouts.handshake,
                    )
                    .await?;
                match reply {
                    RelayCmd::IntroduceAck => Ok(client_intro),
                    _ => Err(NetError::Protocol("unexpected introduction reply".into())),
                }
                // The intro circuit is dropped (destroyed) here.
            };
            match attempt.await {
                Ok(client_intro) => {
                    introduced = Some((client_intro, intro_relay.nickname));
                    break;
                }
                Err(e) => {
                    warn!(intro = %intro_relay.nickname, error = %e, "introduction failed");
                    problems.push(match e {
                        NetError::Remote {
                            code: ErrorCode::UnknownService,
                            ..
                        } => "service is not registered at its introduction point".to_owned(),
                        other => other.to_string(),
                    });
                }
            }
        }
        let Some((client_intro, intro_point)) = introduced else {
            return Err(FetchError::ServiceUnavailable(format!(
                "no introduction point accepted the request ({})",
                problems.join("; ")
            )));
        };

        // 4. Wait for the service at the rendezvous point.
        let reply = match rp_circuit
            .recv_from_last(Some(config.rendezvous_timeout))
            .await
        {
            Ok(RelayCmd::Rendezvous2 { payload }) => payload,
            Ok(_) => {
                return Err(FetchError::CircuitFailed(
                    "unexpected rendezvous message".into(),
                ));
            }
            Err(NetError::Timeout) => {
                return Err(FetchError::ServiceUnavailable(
                    "the service did not arrive at the rendezvous point".into(),
                ));
            }
            Err(e) => return Err(FetchError::CircuitFailed(e.to_string())),
        };
        let keys = client_intro
            .finish(&reply)
            .map_err(|e| FetchError::IdentityMismatch(e.to_string()))?;

        let route = SessionRoute {
            entry: rp_path.entry.nickname.clone(),
            middle: rp_path.middle.nickname.clone(),
            rendezvous: rendezvous.nickname.clone(),
            intro_point,
        };
        info!(
            rendezvous = %route.rendezvous,
            intro = %route.intro_point,
            "MORP session established"
        );
        // 5. End-to-end session over the joined circuits.
        Ok((
            ClientSession::start(rp_circuit.into_stream_pipe(), keys),
            route,
        ))
    }
}
