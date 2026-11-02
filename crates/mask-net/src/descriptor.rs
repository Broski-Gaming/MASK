//! Signed relay descriptors and the local directory.
//!
//! A descriptor binds a relay's address, role, and current onion key to its
//! Ed25519 identity with a signature. Relays write theirs to a directory
//! folder at startup; clients load that folder, verify every signature, and
//! pick a path.
//!
//! The directory folder itself is trusted: whoever can write to it chooses
//! which relays clients use. That is acceptable for a single-machine
//! prototype and is listed as a limitation in docs/MORP.md.

use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::NetError;
use crate::crypto::CryptoError;
use crate::crypto::keys::RelayKeys;
use crate::identity::{NodeId, Role, from_hex, to_hex};
use crate::protocol::MORP_VERSION;

const SIGNING_DOMAIN: &[u8] = b"MORP-v1 relay descriptor\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayDescriptor {
    pub nickname: String,
    pub role: Role,
    pub addr: SocketAddr,
    pub node_id: NodeId,
    pub onion_key: [u8; 32],
    /// Unix time (seconds) when the descriptor was signed.
    pub published: u64,
    signature: [u8; 64],
}

/// The fields covered by the signature, in a fixed binary encoding.
#[derive(Serialize)]
struct Signed<'a> {
    version: u16,
    nickname: &'a str,
    role: Role,
    addr: SocketAddr,
    node_id: &'a NodeId,
    onion_key: &'a [u8; 32],
    published: u64,
}

/// On-disk JSON form.
#[derive(Serialize, Deserialize)]
struct DescriptorFile {
    morp_version: u16,
    nickname: String,
    role: Role,
    address: SocketAddr,
    identity: String,
    onion_key: String,
    published: u64,
    signature: String,
}

impl RelayDescriptor {
    pub fn sign(keys: &RelayKeys, nickname: &str, role: Role, addr: SocketAddr) -> Self {
        let published = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut descriptor = Self {
            nickname: nickname.to_owned(),
            role,
            addr,
            node_id: keys.node_id(),
            onion_key: keys.onion_public(),
            published,
            signature: [0; 64],
        };
        descriptor.signature = keys.sign(&descriptor.signed_bytes());
        descriptor
    }

    fn signed_bytes(&self) -> Vec<u8> {
        let fields = Signed {
            version: MORP_VERSION,
            nickname: &self.nickname,
            role: self.role,
            addr: self.addr,
            node_id: &self.node_id,
            onion_key: &self.onion_key,
            published: self.published,
        };
        let mut bytes = SIGNING_DOMAIN.to_vec();
        bytes.extend(crate::protocol::encode(&fields));
        bytes
    }

    /// Check the signature against the descriptor's own identity key.
    pub fn verify(&self) -> Result<(), CryptoError> {
        let key = VerifyingKey::from_bytes(self.node_id.as_bytes())
            .map_err(|_| CryptoError::BadSignature)?;
        let signature = Signature::from_bytes(&self.signature);
        key.verify_strict(&self.signed_bytes(), &signature)
            .map_err(|_| CryptoError::BadSignature)
    }

    pub fn to_json(&self) -> String {
        let file = DescriptorFile {
            morp_version: MORP_VERSION,
            nickname: self.nickname.clone(),
            role: self.role,
            address: self.addr,
            identity: to_hex(self.node_id.as_bytes()),
            onion_key: to_hex(&self.onion_key),
            published: self.published,
            signature: to_hex(&self.signature),
        };
        serde_json::to_string_pretty(&file).expect("descriptor serializes")
    }

    /// Parse and verify a descriptor.
    pub fn from_json(json: &str) -> Result<Self, NetError> {
        let file: DescriptorFile = serde_json::from_str(json)
            .map_err(|e| NetError::Descriptor(format!("invalid JSON: {e}")))?;
        if file.morp_version != MORP_VERSION {
            return Err(NetError::Descriptor(format!(
                "MORP version {} not supported",
                file.morp_version
            )));
        }
        let bad = |field: &str| NetError::Descriptor(format!("invalid {field}"));
        let descriptor = Self {
            nickname: file.nickname,
            role: file.role,
            addr: file.address,
            node_id: NodeId::from_bytes(from_hex(&file.identity).ok_or_else(|| bad("identity"))?),
            onion_key: from_hex(&file.onion_key).ok_or_else(|| bad("onion_key"))?,
            published: file.published,
            signature: from_hex(&file.signature).ok_or_else(|| bad("signature"))?,
        };
        descriptor.verify().map_err(|_| {
            NetError::Descriptor(format!("bad signature on {}", descriptor.nickname))
        })?;
        Ok(descriptor)
    }

    /// Write `<dir>/<nickname>.json` atomically (temp file + rename).
    pub fn write_to_dir(&self, dir: &Path) -> std::io::Result<PathBuf> {
        fs::create_dir_all(dir)?;
        let path = Self::path_in(dir, &self.nickname);
        let tmp = path.with_extension("json.tmp");
        let mut file = fs::File::create(&tmp)?;
        file.write_all(self.to_json().as_bytes())?;
        file.sync_all()?;
        fs::rename(&tmp, &path)?;
        Ok(path)
    }

    pub fn path_in(dir: &Path, nickname: &str) -> PathBuf {
        let safe: String = nickname
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        dir.join(format!("{safe}.json"))
    }

    #[cfg(test)]
    pub(crate) fn signature_mut(&mut self) -> &mut [u8; 64] {
        &mut self.signature
    }
}

/// The three relays of a circuit, in order. The last hop is an exit (echo
/// test service) or a rendezvous-role relay (hidden services).
#[derive(Clone, Debug)]
pub struct CircuitPath {
    pub entry: RelayDescriptor,
    pub middle: RelayDescriptor,
    pub last: RelayDescriptor,
}

impl CircuitPath {
    pub fn new(
        entry: RelayDescriptor,
        middle: RelayDescriptor,
        last: RelayDescriptor,
    ) -> Result<Self, NetError> {
        let path = Self {
            entry,
            middle,
            last,
        };
        let role_ok = [
            path.entry.role == Role::Entry,
            path.middle.role == Role::Middle,
            path.last.role.is_last_hop(),
        ];
        for (d, ok) in path.hops().into_iter().zip(role_ok) {
            if !ok {
                return Err(NetError::InvalidConfig(format!(
                    "{} is a {} relay, which cannot be used in that position",
                    d.nickname, d.role
                )));
            }
            if !d.addr.ip().is_loopback() {
                return Err(NetError::NotLoopback(d.addr));
            }
        }
        let ids = [path.entry.node_id, path.middle.node_id, path.last.node_id];
        if ids[0] == ids[1] || ids[1] == ids[2] || ids[0] == ids[2] {
            return Err(NetError::InvalidConfig(
                "a path must use three different relays".into(),
            ));
        }
        Ok(path)
    }

    pub fn hops(&self) -> [&RelayDescriptor; 3] {
        [&self.entry, &self.middle, &self.last]
    }
}

/// Verified descriptors loaded from a directory folder.
#[derive(Clone, Debug, Default)]
pub struct Directory {
    relays: Vec<RelayDescriptor>,
}

impl Directory {
    /// Load every `*.json` in `dir`. Invalid descriptors are skipped and
    /// reported in the returned list of problems.
    pub fn load(dir: &Path) -> Result<(Self, Vec<String>), NetError> {
        let entries = fs::read_dir(dir).map_err(|e| {
            NetError::Descriptor(format!("cannot read directory {}: {e}", dir.display()))
        })?;
        let mut relays = Vec::new();
        let mut problems = Vec::new();
        for entry in entries {
            let path = entry?.path();
            if path.extension().is_none_or(|ext| ext != "json") {
                continue;
            }
            match fs::read_to_string(&path)
                .map_err(NetError::from)
                .and_then(|json| RelayDescriptor::from_json(&json))
            {
                Ok(d) => relays.push(d),
                Err(e) => problems.push(format!("{}: {e}", path.display())),
            }
        }
        relays.sort_by(|a, b| a.nickname.cmp(&b.nickname));
        Ok((Self { relays }, problems))
    }

    pub fn from_descriptors(relays: Vec<RelayDescriptor>) -> Result<Self, NetError> {
        for d in &relays {
            d.verify()
                .map_err(|_| NetError::Descriptor(format!("bad signature on {}", d.nickname)))?;
        }
        Ok(Self { relays })
    }

    pub fn relays(&self) -> &[RelayDescriptor] {
        &self.relays
    }

    /// A uniformly random relay with `role`, avoiding `avoid` if possible.
    pub fn random_relay(&self, role: Role, avoid: &[NodeId]) -> Option<RelayDescriptor> {
        let all: Vec<_> = self.relays.iter().filter(|d| d.role == role).collect();
        let preferred: Vec<_> = all
            .iter()
            .copied()
            .filter(|d| !avoid.contains(&d.node_id))
            .collect();
        let pool = if preferred.is_empty() { all } else { preferred };
        if pool.is_empty() {
            return None;
        }
        let index = u64::from_le_bytes(crate::crypto::random_bytes::<8>()) as usize % pool.len();
        Some(pool[index].clone())
    }

    /// The relay with this identity, if the directory has it.
    pub fn find(&self, node_id: &NodeId) -> Option<&RelayDescriptor> {
        self.relays.iter().find(|d| d.node_id == *node_id)
    }

    /// Random entry and middle, ending at `last`.
    pub fn path_ending_at(&self, last: &RelayDescriptor) -> Result<CircuitPath, NetError> {
        let missing =
            |role: Role| NetError::InvalidConfig(format!("no {role} relay in the directory"));
        let entry = self
            .random_relay(Role::Entry, &[])
            .ok_or_else(|| missing(Role::Entry))?;
        let middle = self
            .random_relay(Role::Middle, &[])
            .ok_or_else(|| missing(Role::Middle))?;
        CircuitPath::new(entry, middle, last.clone())
    }

    /// Random entry → middle → exit path (echo test service).
    pub fn choose_path(&self) -> Result<CircuitPath, NetError> {
        let exit = self
            .random_relay(Role::Exit, &[])
            .ok_or_else(|| NetError::InvalidConfig("no exit relay in the directory".into()))?;
        self.path_ending_at(&exit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(role: Role, port: u16) -> (RelayKeys, RelayDescriptor) {
        let keys = RelayKeys::generate();
        let d = RelayDescriptor::sign(
            &keys,
            &role.to_string(),
            role,
            SocketAddr::from(([127, 0, 0, 1], port)),
        );
        (keys, d)
    }

    #[test]
    fn signed_descriptor_verifies_and_round_trips_through_json() {
        let (_, d) = descriptor(Role::Middle, 7102);
        d.verify().unwrap();
        assert_eq!(RelayDescriptor::from_json(&d.to_json()).unwrap(), d);
    }

    #[test]
    fn any_changed_field_breaks_the_signature() {
        let (_, d) = descriptor(Role::Entry, 7101);
        let (other, _) = descriptor(Role::Entry, 7101);

        let mut moved = d.clone();
        moved.addr.set_port(9999);
        assert!(moved.verify().is_err());

        let mut swapped_key = d.clone();
        swapped_key.onion_key = other.onion_public();
        assert!(swapped_key.verify().is_err());

        let mut new_role = d.clone();
        new_role.role = Role::Exit;
        assert!(new_role.verify().is_err());

        let mut bad_sig = d.clone();
        bad_sig.signature_mut()[10] ^= 1;
        assert!(bad_sig.verify().is_err());
    }

    #[test]
    fn tampered_json_is_rejected() {
        let (_, d) = descriptor(Role::Exit, 7103);
        let json = d.to_json().replace("7103", "7104");
        assert!(matches!(
            RelayDescriptor::from_json(&json),
            Err(NetError::Descriptor(_))
        ));
    }

    #[test]
    fn directory_loads_valid_and_reports_invalid_files() {
        let dir = tempfile::tempdir().unwrap();
        for (role, port) in [
            (Role::Entry, 7101),
            (Role::Middle, 7102),
            (Role::Exit, 7103),
        ] {
            descriptor(role, port).1.write_to_dir(dir.path()).unwrap();
        }
        fs::write(dir.path().join("broken.json"), "{ not json").unwrap();
        fs::write(dir.path().join("notes.txt"), "ignored").unwrap();

        let (directory, problems) = Directory::load(dir.path()).unwrap();
        assert_eq!(directory.relays().len(), 3);
        assert_eq!(problems.len(), 1);
        let path = directory.choose_path().unwrap();
        assert_eq!(path.middle.role, Role::Middle);
    }

    #[test]
    fn path_needs_three_distinct_relays_in_role_order() {
        let (_, e) = descriptor(Role::Entry, 7101);
        let (_, m) = descriptor(Role::Middle, 7102);
        let (_, x) = descriptor(Role::Exit, 7103);
        assert!(CircuitPath::new(e.clone(), m.clone(), x.clone()).is_ok());
        assert!(CircuitPath::new(m.clone(), e.clone(), x.clone()).is_err());
        assert!(Directory::default().choose_path().is_err());
    }
}
