//! Talking to directory authorities.
//!
//! Every request opens a Noise NK link to an authority using the link key
//! pinned in `network.toml`, so answers come from the real authority and the
//! network cannot see or change them. Answers are still verified: consensus
//! signatures and service descriptor signatures are checked here.

use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::consensus::{CLOCK_SKEW, Consensus, SignedConsensus};
use super::{
    AuthorityStatus, DIR_PROTOCOL_VERSION, DirErrorCode, DirRequest, DirRequestBody, DirResponse,
};
use crate::NetError;
use crate::address::MorpAddress;
use crate::config::{AuthorityInfo, NetworkConfig};
use crate::descriptor::RelayDescriptor;
use crate::directory::client::LookupError;
use crate::protocol::{decode, encode};
use crate::service::descriptor::{ServiceDescriptor, Withdrawal};
use crate::service::now_secs;
use crate::transport::{ConnectPolicy, Connection, LinkKind, Timeouts};
use crate::trust::TrustedRelays;

#[derive(Clone, Debug)]
pub struct AuthorityClient {
    network: Arc<NetworkConfig>,
    policy: ConnectPolicy,
    timeouts: Timeouts,
    origin: String,
}

impl AuthorityClient {
    pub fn new(network: NetworkConfig) -> Self {
        let policy = ConnectPolicy::allow_all().with_scope(network.scope);
        Self {
            network: Arc::new(network),
            policy,
            timeouts: Timeouts::default(),
            origin: "client".into(),
        }
    }

    /// Use `policy` (its scope is replaced by the network's scope).
    pub fn with_policy(mut self, policy: ConnectPolicy, origin: &str) -> Self {
        self.policy = policy.with_scope(self.network.scope);
        self.origin = origin.to_owned();
        self
    }

    pub fn with_timeouts(mut self, timeouts: Timeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    pub fn network(&self) -> &NetworkConfig {
        &self.network
    }

    async fn request(
        &self,
        authority: &AuthorityInfo,
        body: DirRequestBody,
    ) -> Result<DirResponse, NetError> {
        let mut conn = Connection::connect_checked(
            authority.address,
            LinkKind::Directory,
            &authority.link_key,
            None,
            &self.timeouts,
            &self.policy,
            &self.origin,
        )
        .await?;
        conn.send_bytes(&encode(&DirRequest {
            version: DIR_PROTOCOL_VERSION,
            body,
        }))
        .await?;
        let reply = conn
            .recv_bytes(self.timeouts.response)
            .await?
            .ok_or(NetError::ConnectionClosed)?;
        let mut response: DirResponse = decode(&reply)?;
        // Free text from the other side is made safe to print and log.
        if let DirResponse::Ok { detail } | DirResponse::Error { detail, .. } = &mut response {
            *detail = crate::protocol::sanitize_remote_text(detail);
        }
        Ok(response)
    }

    /// Authorities in random order, so load spreads across them.
    fn shuffled(&self) -> Vec<&AuthorityInfo> {
        let mut list: Vec<&AuthorityInfo> = self.network.authorities.iter().collect();
        for i in (1..list.len()).rev() {
            let j = u64::from_le_bytes(crate::crypto::random_bytes::<8>()) as usize % (i + 1);
            list.swap(i, j);
        }
        list
    }

    /// The newest valid consensus any authority offers.
    pub async fn fetch_consensus(&self) -> Result<Consensus, NetError> {
        let mut best: Option<Consensus> = None;
        let mut problems = Vec::new();
        for authority in self.shuffled() {
            let outcome = match self.request(authority, DirRequestBody::GetConsensus).await {
                Ok(DirResponse::Consensus { document }) => SignedConsensus::from_bytes(&document)
                    .and_then(|doc| doc.verify(&self.network, now_secs())),
                Ok(DirResponse::Error { detail, .. }) => Err(NetError::Protocol(detail)),
                Ok(_) => Err(NetError::Protocol("unexpected answer".into())),
                Err(e) => Err(e),
            };
            match outcome {
                Ok(c) if best.as_ref().is_none_or(|b| c.sequence > b.sequence) => best = Some(c),
                Ok(_) => {}
                Err(e) => {
                    warn!(authority = %authority.name, error = %e, "consensus fetch failed");
                    problems.push(format!("{}: {e}", authority.name));
                }
            }
        }
        best.ok_or_else(|| {
            NetError::Untrusted(format!("no valid consensus ({})", problems.join("; ")))
        })
    }

    /// Fetch a consensus and install it in `trusted` if it is newer.
    /// Returns the number of relays installed, or `None` if ours was current.
    pub async fn refresh(&self, trusted: &TrustedRelays) -> Result<Option<usize>, NetError> {
        let consensus = self.fetch_consensus().await?;
        if trusted
            .consensus_sequence()
            .is_some_and(|s| consensus.sequence <= s)
        {
            return Ok(None);
        }
        let relays = crate::trust::cap_per_ip(
            consensus.relays,
            self.network.relay_policy.max_relays_per_ip,
        );
        let installed = trusted.install_consensus(
            consensus.sequence,
            consensus.fresh_until,
            consensus.valid_until + CLOCK_SKEW,
            relays,
        )?;
        debug!(
            sequence = consensus.sequence,
            relays = installed,
            "consensus installed"
        );
        Ok(Some(installed))
    }

    /// Refresh only if the installed consensus is missing or stale.
    pub async fn refresh_if_needed(&self, trusted: &TrustedRelays) -> Result<(), NetError> {
        if trusted.needs_refresh() {
            match self.refresh(trusted).await {
                Ok(_) => {}
                // Keep using a stale-but-valid consensus if authorities are down.
                Err(e) if trusted.snapshot().is_ok() => {
                    warn!(error = %e, "could not refresh the consensus; using the current one");
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Upload a relay descriptor to every authority.
    pub async fn publish_relay(
        &self,
        descriptor: &RelayDescriptor,
    ) -> Vec<(String, Result<String, NetError>)> {
        let mut results = Vec::new();
        for authority in &self.network.authorities {
            let outcome = match self
                .request(
                    authority,
                    DirRequestBody::PublishRelay {
                        descriptor: descriptor.to_wire(),
                    },
                )
                .await
            {
                Ok(DirResponse::Ok { detail }) => Ok(detail),
                Ok(DirResponse::Error { code, detail }) => Err(match code {
                    DirErrorCode::NotApproved => NetError::Untrusted(detail),
                    _ => NetError::Protocol(detail),
                }),
                Ok(_) => Err(NetError::Protocol("unexpected answer".into())),
                Err(e) => Err(e),
            };
            results.push((authority.name.clone(), outcome));
        }
        results
    }

    /// Find and verify the descriptor for `address`.
    pub async fn lookup_service(
        &self,
        address: &MorpAddress,
    ) -> Result<Option<ServiceDescriptor>, LookupError> {
        let mut problems = Vec::new();
        let mut not_found = false;
        for authority in self.shuffled() {
            let body = DirRequestBody::LookupService { id: address.id() };
            match self.request(authority, body).await {
                Ok(DirResponse::Service {
                    descriptor: Some(json),
                }) => {
                    // Never trust the directory: verify everything ourselves.
                    let descriptor = ServiceDescriptor::from_json(&json)
                        .map_err(|e| LookupError::Invalid(e.to_string()))?;
                    if descriptor.address != *address {
                        return Err(LookupError::Invalid(
                            "descriptor is for a different address".into(),
                        ));
                    }
                    descriptor
                        .verify(now_secs())
                        .map_err(|e| LookupError::Invalid(e.to_string()))?;
                    return Ok(Some(descriptor));
                }
                Ok(DirResponse::Service { descriptor: None }) => not_found = true,
                Ok(DirResponse::Error { detail, .. }) => problems.push(detail),
                Ok(_) => problems.push("unexpected answer".into()),
                Err(e) => problems.push(format!("{}: {e}", authority.name)),
            }
        }
        if not_found {
            Ok(None)
        } else {
            Err(LookupError::Unavailable(problems.join("; ")))
        }
    }

    async fn to_all(&self, make: impl Fn() -> DirRequestBody) -> Result<(), NetError> {
        let mut problems = Vec::new();
        let mut accepted = false;
        for authority in &self.network.authorities {
            match self.request(authority, make()).await {
                Ok(DirResponse::Ok { .. }) => accepted = true,
                Ok(DirResponse::Error { detail, .. }) => {
                    problems.push(format!("{}: {detail}", authority.name))
                }
                Ok(_) => problems.push(format!("{}: unexpected answer", authority.name)),
                Err(e) => problems.push(format!("{}: {e}", authority.name)),
            }
        }
        if accepted {
            for problem in &problems {
                warn!("authority refused: {problem}");
            }
            Ok(())
        } else {
            Err(NetError::Protocol(format!(
                "no authority accepted it ({})",
                problems.join("; ")
            )))
        }
    }

    /// Publish a service descriptor to every authority (succeeds if any accepts).
    pub async fn publish_service(&self, descriptor: &ServiceDescriptor) -> Result<(), NetError> {
        let id = descriptor.address.id();
        let json = descriptor.to_json();
        self.to_all(|| DirRequestBody::PublishService {
            id: id.clone(),
            descriptor: json.clone(),
        })
        .await
    }

    pub async fn withdraw_service(&self, withdrawal: &Withdrawal) -> Result<(), NetError> {
        let address = MorpAddress::parse_host(&withdrawal.address)
            .map_err(|e| NetError::InvalidConfig(e.to_string()))?;
        let id = address.id();
        let json = serde_json::to_string(withdrawal).expect("withdrawal serializes");
        self.to_all(|| DirRequestBody::WithdrawService {
            id: id.clone(),
            withdrawal: json.clone(),
        })
        .await
    }

    /// Each authority's status (for `mask-authority status`).
    pub async fn status(&self) -> Vec<(String, Result<AuthorityStatus, NetError>)> {
        let mut out = Vec::new();
        for authority in &self.network.authorities {
            let status = match self.request(authority, DirRequestBody::Status).await {
                Ok(DirResponse::Status(status)) => Ok(status),
                Ok(DirResponse::Error { detail, .. }) => Err(NetError::Protocol(detail)),
                Ok(_) => Err(NetError::Protocol("unexpected answer".into())),
                Err(e) => Err(e),
            };
            out.push((authority.name.clone(), status));
        }
        out
    }
}

/// Shortest gap between two consensus fetches triggered by lookup misses.
const MISS_REFRESH_GAP: Duration = Duration::from_secs(2);

/// Keep `trusted` up to date: fetch a consensus every `every`, and early
/// (at most every 2 s) when a lookup misses, until `shutdown` fires.
pub fn spawn_refresher(
    client: AuthorityClient,
    trusted: TrustedRelays,
    every: Duration,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        let mut last_fetch: Option<tokio::time::Instant> = None;
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = trusted.lookup_missed() => {
                    if let Some(at) = last_fetch {
                        let wait = MISS_REFRESH_GAP.saturating_sub(at.elapsed());
                        tokio::select! {
                            _ = tokio::time::sleep(wait) => {}
                            _ = shutdown.cancelled() => return,
                        }
                    }
                }
                _ = shutdown.cancelled() => return,
            }
            last_fetch = Some(tokio::time::Instant::now());
            match client.refresh(&trusted).await {
                Ok(Some(n)) => info!(relays = n, "installed a new consensus"),
                Ok(None) => {}
                Err(e) => warn!(error = %e, "consensus refresh failed"),
            }
        }
    })
}
