//! Directory authorities: relay admission, signed consensus documents, and
//! the `.morp` service directory for a multi-machine MORP testnet (v0.6).
//!
//! ```text
//! relay ──(upload signed descriptor)──▶ authority ──(probe over Noise)──▶ relay
//!                                          │
//!            signed, expiring consensus ◀──┘──▶ clients, relays, services
//! ```
//!
//! - An authority has a long-term **Ed25519 identity** (signs consensus
//!   documents) and a long-term **X25519 link key** (its Noise key). Both
//!   public keys are pinned in every machine's `network.toml`.
//! - Relays upload their self-signed descriptors. The authority admits a
//!   relay only if its nickname is on `approved-relays.toml` **with the same
//!   identity key and role** (identity changes are refused), its address is
//!   inside the network scope, and a health probe proves it is reachable and
//!   holds the link key in its descriptor.
//! - Every `consensus_interval` (and whenever the set changes) the authority
//!   signs a consensus: the running relays, a sequence number, and validity
//!   times. Clients accept only a consensus signed by a pinned authority, for
//!   their network name, not expired, and newer than the one they have.
//! - Hidden services publish their signed descriptors to the authority and
//!   clients look them up there (same rules as the v0.4 localhost directory:
//!   cryptographic addresses only, no names, no listing).
//!
//! All requests travel over Noise NK links ([`LinkKind::Directory`]), so the
//! network cannot read which `.morp` address a client looks up or tamper
//! with answers, and a client knows it reached the real authority.
//!
//! **Limits (v0.6):** each authority signs its own consensus; with several
//! authorities a client uses the newest valid one from any of them. There is
//! no vote or threshold signature yet, so a single compromised authority can
//! add relays it controls. The operator runs every relay: no anonymity.
//!
//! [`LinkKind::Directory`]: crate::transport::LinkKind::Directory

pub mod client;
pub mod consensus;
pub mod server;

use std::io;
use std::path::Path;

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::keys::{create_private_dir, read_secret, write_new_secret};
use crate::identity::Role;

/// Directory protocol version (checked on every request).
pub const DIR_PROTOCOL_VERSION: u16 = 1;
/// Default authority port.
pub const DEFAULT_AUTHORITY_PORT: u16 = 7300;

const IDENTITY_FILE: &str = "authority.key";
const LINK_FILE: &str = "link.key";

/// An authority's long-term keys, stored as two 0600 files.
pub struct AuthorityKeys {
    identity: SigningKey,
    link: StaticSecret,
}

impl AuthorityKeys {
    pub fn generate() -> Self {
        Self {
            identity: SigningKey::from_bytes(&crate::crypto::random_bytes()),
            link: StaticSecret::from(crate::crypto::random_bytes::<32>()),
        }
    }

    /// Load both keys from `data_dir` (mode 0700), creating them on first
    /// run. Refuses key files readable by group or others.
    pub fn load_or_create(data_dir: &Path) -> io::Result<Self> {
        create_private_dir(data_dir, true)?;
        let load = |name: &str| {
            let path = data_dir.join(name);
            match read_secret(&path) {
                Ok(seed) => Ok(seed),
                Err(e) if e.kind() == io::ErrorKind::NotFound => write_new_secret(&path),
                Err(e) => Err(e),
            }
        };
        let identity = load(IDENTITY_FILE)?;
        let link = load(LINK_FILE)?;
        Ok(Self {
            identity: SigningKey::from_bytes(&identity),
            link: StaticSecret::from(*link),
        })
    }

    pub fn identity_public(&self) -> [u8; 32] {
        self.identity.verifying_key().to_bytes()
    }

    pub fn link_public(&self) -> [u8; 32] {
        PublicKey::from(&self.link).to_bytes()
    }

    pub(crate) fn link_secret(&self) -> &StaticSecret {
        &self.link
    }

    pub(crate) fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.identity.sign(message).to_bytes()
    }
}

/// One request to an authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirRequest {
    pub version: u16,
    pub body: DirRequestBody,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DirRequestBody {
    /// A relay uploads its descriptor (binary form, self-signed).
    PublishRelay { descriptor: Vec<u8> },
    /// The latest signed consensus.
    GetConsensus,
    /// A service descriptor by `.morp` id (56 characters).
    LookupService { id: String },
    /// Publish a signed service descriptor (JSON).
    PublishService { id: String, descriptor: String },
    /// Withdraw a service descriptor (signed JSON withdrawal).
    WithdrawService { id: String, withdrawal: String },
    /// Relay health overview for operators.
    Status,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DirResponse {
    Ok {
        detail: String,
    },
    /// An encoded [`consensus::SignedConsensus`].
    Consensus {
        document: Vec<u8>,
    },
    Service {
        descriptor: Option<String>,
    },
    Status(AuthorityStatus),
    Error {
        code: DirErrorCode,
        detail: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DirErrorCode {
    BadRequest,
    /// The relay is not on the allowlist, or claims another identity/role.
    NotApproved,
    Invalid,
    NotFound,
    Conflict,
    Unavailable,
    ResourceLimit,
    VersionMismatch,
}

/// What `mask-authority status` shows.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorityStatus {
    pub name: String,
    pub network: String,
    pub consensus_sequence: Option<u64>,
    pub consensus_valid_until: Option<u64>,
    pub relays: Vec<RelayStatus>,
    pub identity_changes_refused: u64,
    pub unapproved_uploads: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayStatus {
    pub nickname: String,
    pub role: Role,
    pub address: std::net::SocketAddr,
    pub family: String,
    /// Authority-assigned operator (empty: unknown).
    pub operator: String,
    /// How long ago the authority first listed the relay.
    pub listed_for_secs: Option<u64>,
    /// In the current consensus (passed its latest health probes).
    pub running: bool,
    pub consecutive_probe_failures: u32,
    pub seconds_since_upload: u64,
    pub seconds_since_probe: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn keys_persist_with_private_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("auth");
        let first = AuthorityKeys::load_or_create(&data).unwrap();
        let second = AuthorityKeys::load_or_create(&data).unwrap();
        assert_eq!(first.identity_public(), second.identity_public());
        assert_eq!(first.link_public(), second.link_public());
        assert_ne!(first.identity_public(), first.link_public());
        for file in [IDENTITY_FILE, LINK_FILE] {
            let mode = std::fs::metadata(data.join(file))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{file}");
        }
        let mode = std::fs::metadata(&data).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }
}
