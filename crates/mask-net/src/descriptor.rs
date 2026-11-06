//! Signed relay descriptors and path selection.
//!
//! A descriptor binds a relay's address, role, family, current onion key,
//! and current link key to its Ed25519 identity with a signature.
//!
//! Where descriptors come from depends on the mode (see [`crate::trust`]):
//! - **local** (one machine): relays write theirs to a folder, which is
//!   trusted completely (whoever can write to it chooses the relays);
//! - **network** (v0.6): relays upload them to directory authorities, which
//!   admit only allowlisted identities and sign a consensus.
//!
//! Either way every descriptor's own signature is verified before use.

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

const SIGNING_DOMAIN: &[u8] = b"MORP-v3 relay descriptor\0";

/// Longest family label (an operator-chosen name for one machine).
pub const MAX_FAMILY_LEN: usize = 32;
/// Longest nickname.
pub const MAX_NICKNAME_LEN: usize = 32;

/// Nicknames and families: 1-32 characters of `a-z 0-9 - _` (families may
/// also be empty, meaning "a family of its own").
pub fn valid_label(label: &str, max: usize) -> bool {
    label.len() <= max
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayDescriptor {
    pub nickname: String,
    pub role: Role,
    pub addr: SocketAddr,
    pub node_id: NodeId,
    pub onion_key: [u8; 32],
    /// X25519 static key for Noise link handshakes (fresh each run).
    pub link_key: [u8; 32],
    /// Operator-assigned machine label. Paths avoid putting two hops from
    /// the same family on one circuit. Empty: a family of its own.
    pub family: String,
    /// Unix time (seconds) when the descriptor was signed.
    pub published: u64,
    signature: [u8; 64],
    /// Who runs the relay, as assigned by the directory authority (v0.7).
    /// **Not** covered by the relay's own signature: it comes from the
    /// consensus, which the authority signs. Empty: unknown (local mode).
    pub operator: String,
    /// Unix time when the authority first listed this relay (v0.7), from
    /// the consensus. 0: unknown (local mode).
    pub listed_since: u64,
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
    link_key: &'a [u8; 32],
    family: &'a str,
    published: u64,
}

/// Compact binary form, used inside signed consensus documents.
#[derive(Serialize, Deserialize)]
struct DescriptorWire {
    nickname: String,
    role: Role,
    addr: SocketAddr,
    node_id: NodeId,
    onion_key: [u8; 32],
    link_key: [u8; 32],
    family: String,
    published: u64,
    signature: Vec<u8>,
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
    link_key: String,
    #[serde(default)]
    family: String,
    published: u64,
    signature: String,
}

impl RelayDescriptor {
    pub fn sign(keys: &RelayKeys, nickname: &str, role: Role, addr: SocketAddr) -> Self {
        Self::sign_with_family(keys, nickname, role, addr, "")
    }

    pub fn sign_with_family(
        keys: &RelayKeys,
        nickname: &str,
        role: Role,
        addr: SocketAddr,
        family: &str,
    ) -> Self {
        Self::sign_claiming(
            keys,
            nickname,
            role,
            addr,
            family,
            keys.onion_public(),
            keys.link_public(),
        )
    }

    /// Sign a descriptor that claims arbitrary onion and link keys. Real
    /// relays never do this; it exists so tests can play a hostile relay
    /// that copies another relay's keys (anyone can publish someone else's
    /// *public* keys, so this gives an attacker nothing new).
    pub fn sign_claiming(
        keys: &RelayKeys,
        nickname: &str,
        role: Role,
        addr: SocketAddr,
        family: &str,
        onion_key: [u8; 32],
        link_key: [u8; 32],
    ) -> Self {
        let published = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut descriptor = Self {
            nickname: nickname.to_owned(),
            role,
            addr,
            node_id: keys.node_id(),
            onion_key,
            link_key,
            family: family.to_owned(),
            published,
            signature: [0; 64],
            operator: String::new(),
            listed_since: 0,
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
            link_key: &self.link_key,
            family: &self.family,
            published: self.published,
        };
        let mut bytes = SIGNING_DOMAIN.to_vec();
        bytes.extend(crate::protocol::encode(&fields));
        bytes
    }

    /// Check the signature against the descriptor's own identity key.
    pub fn verify(&self) -> Result<(), CryptoError> {
        if !valid_label(&self.nickname, MAX_NICKNAME_LEN)
            || self.nickname.is_empty()
            || !valid_label(&self.family, MAX_FAMILY_LEN)
        {
            return Err(CryptoError::BadSignature);
        }
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
            link_key: to_hex(&self.link_key),
            family: self.family.clone(),
            published: self.published,
            signature: to_hex(&self.signature),
        };
        serde_json::to_string_pretty(&file).expect("descriptor serializes")
    }

    /// Compact binary encoding (for consensus documents).
    pub fn to_wire(&self) -> Vec<u8> {
        crate::protocol::encode(&DescriptorWire {
            nickname: self.nickname.clone(),
            role: self.role,
            addr: self.addr,
            node_id: self.node_id,
            onion_key: self.onion_key,
            link_key: self.link_key,
            family: self.family.clone(),
            published: self.published,
            signature: self.signature.to_vec(),
        })
    }

    /// Decode and verify a binary descriptor.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, NetError> {
        let wire: DescriptorWire = crate::protocol::decode(bytes)
            .map_err(|e| NetError::Descriptor(format!("malformed descriptor: {e}")))?;
        let descriptor = Self {
            nickname: wire.nickname,
            role: wire.role,
            addr: wire.addr,
            node_id: wire.node_id,
            onion_key: wire.onion_key,
            link_key: wire.link_key,
            family: wire.family,
            published: wire.published,
            signature: wire
                .signature
                .try_into()
                .map_err(|_| NetError::Descriptor("malformed signature".into()))?,
            operator: String::new(),
            listed_since: 0,
        };
        descriptor.verify().map_err(|_| {
            NetError::Descriptor(format!("bad signature on {}", descriptor.nickname))
        })?;
        Ok(descriptor)
    }

    /// The family used for path diversity: the declared one, or the relay's
    /// own identity if none was declared.
    pub fn family_key(&self) -> String {
        if self.family.is_empty() {
            format!("id:{}", self.node_id)
        } else {
            self.family.clone()
        }
    }

    /// The operator used for path diversity: the authority-assigned one, or
    /// the relay's own identity if unknown.
    pub fn operator_key(&self) -> String {
        if self.operator.is_empty() {
            format!("id:{}", self.node_id)
        } else {
            self.operator.clone()
        }
    }

    /// Same relay, same family (machine), or same operator. Two related
    /// relays must not be the two ends of one circuit: together they would
    /// see where the circuit starts and where it ends.
    pub fn related_to(&self, other: &RelayDescriptor) -> bool {
        self.node_id == other.node_id
            || self.family_key() == other.family_key()
            || self.operator_key() == other.operator_key()
    }

    /// Same address network ([`subnet_key`](Self::subnet_key)).
    pub fn same_subnet(&self, other: &RelayDescriptor) -> bool {
        self.subnet_key() == other.subnet_key()
    }

    /// The network the relay's address belongs to, for path diversity: the
    /// IPv4 /16 or the IPv6 /32 (as Tor uses). Relays on one network are
    /// more likely to be watched by the same observer.
    pub fn subnet_key(&self) -> String {
        match self.addr.ip() {
            std::net::IpAddr::V4(ip) => {
                let [a, b, _, _] = ip.octets();
                format!("{a}.{b}.0.0/16")
            }
            std::net::IpAddr::V6(ip) => {
                let s = ip.segments();
                format!("{:x}:{:x}::/32", s[0], s[1])
            }
        }
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
            link_key: from_hex(&file.link_key).ok_or_else(|| bad("link_key"))?,
            family: file.family,
            published: file.published,
            signature: from_hex(&file.signature).ok_or_else(|| bad("signature"))?,
            operator: String::new(),
            listed_since: 0,
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

fn random_element<T>(items: &[T]) -> &T {
    let index = u64::from_le_bytes(crate::crypto::random_bytes::<8>()) as usize % items.len();
    &items[index]
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

    /// A uniformly random relay with `role`. Relays in `avoid` (identities)
    /// are never chosen; relays whose family is in `avoid_families` or that
    /// are in `unhealthy` are skipped unless nothing else is left.
    pub fn pick(
        &self,
        role: Role,
        avoid: &[NodeId],
        avoid_families: &[String],
        unhealthy: &[NodeId],
    ) -> Option<RelayDescriptor> {
        let all: Vec<&RelayDescriptor> = self
            .relays
            .iter()
            .filter(|d| d.role == role && !avoid.contains(&d.node_id))
            .collect();
        let healthy: Vec<_> = all
            .iter()
            .copied()
            .filter(|d| !unhealthy.contains(&d.node_id))
            .collect();
        let diverse: Vec<_> = healthy
            .iter()
            .copied()
            .filter(|d| !avoid_families.contains(&d.family_key()))
            .collect();
        let pool = [diverse, healthy, all]
            .into_iter()
            .find(|pool| !pool.is_empty())?;
        let index = u64::from_le_bytes(crate::crypto::random_bytes::<8>()) as usize % pool.len();
        Some(pool[index].clone())
    }

    /// A uniformly random relay with `role`, avoiding `avoid` if possible.
    pub fn random_relay(&self, role: Role, avoid: &[NodeId]) -> Option<RelayDescriptor> {
        self.pick(role, &[], &[], avoid)
    }

    /// A uniformly random relay with `role` that is not in `exclude`
    /// (never chosen), preferring, in this order: healthy and unrelated to
    /// every relay in `unrelated_to` (other family and operator); healthy;
    /// unrelated; anything left.
    pub fn pick_unrelated(
        &self,
        role: Role,
        exclude: &[NodeId],
        unrelated_to: &[&RelayDescriptor],
        unhealthy: &[NodeId],
    ) -> Option<RelayDescriptor> {
        let all: Vec<&RelayDescriptor> = self
            .relays
            .iter()
            .filter(|d| d.role == role && !exclude.contains(&d.node_id))
            .collect();
        let healthy = |d: &&RelayDescriptor| !unhealthy.contains(&d.node_id);
        let unrelated = |d: &&RelayDescriptor| !unrelated_to.iter().any(|o| d.related_to(o));
        let tiers = [
            all.iter()
                .copied()
                .filter(|d| healthy(d) && unrelated(d))
                .collect::<Vec<_>>(),
            all.iter().copied().filter(healthy).collect(),
            all.iter().copied().filter(unrelated).collect(),
            all.clone(),
        ];
        let pool = tiers.into_iter().find(|t| !t.is_empty())?;
        Some((*random_element(&pool)).clone())
    }

    /// A middle relay for a circuit from `entry` to `last` (both fixed),
    /// preferring, in this order: healthy, unrelated to both ends, and on
    /// another /16 than both; healthy and unrelated to both; healthy;
    /// anything. Never `entry` or `last` itself.
    pub fn middle_between(
        &self,
        entry: &RelayDescriptor,
        last: &RelayDescriptor,
        unhealthy: &[NodeId],
    ) -> Option<RelayDescriptor> {
        let all: Vec<&RelayDescriptor> = self
            .relays
            .iter()
            .filter(|d| {
                d.role == Role::Middle && d.node_id != entry.node_id && d.node_id != last.node_id
            })
            .collect();
        let healthy = |d: &&RelayDescriptor| !unhealthy.contains(&d.node_id);
        let unrelated = |d: &&RelayDescriptor| !d.related_to(entry) && !d.related_to(last);
        let other_net = |d: &&RelayDescriptor| !d.same_subnet(entry) && !d.same_subnet(last);
        let tiers = [
            all.iter()
                .copied()
                .filter(|d| healthy(d) && unrelated(d) && other_net(d))
                .collect::<Vec<_>>(),
            all.iter()
                .copied()
                .filter(|d| healthy(d) && unrelated(d))
                .collect(),
            all.iter().copied().filter(healthy).collect(),
            all.clone(),
        ];
        let pool = tiers.into_iter().find(|t| !t.is_empty())?;
        Some((*random_element(&pool)).clone())
    }

    /// `entry` → (chosen middle) → `last`. The caller picked `entry` (an
    /// entry guard) unrelated to `last`; see [`middle_between`].
    ///
    /// [`middle_between`]: Directory::middle_between
    pub fn path_through(
        &self,
        entry: &RelayDescriptor,
        last: &RelayDescriptor,
        unhealthy: &[NodeId],
    ) -> Result<CircuitPath, NetError> {
        let middle = self
            .middle_between(entry, last, unhealthy)
            .ok_or_else(|| NetError::InvalidConfig("no middle relay in the directory".into()))?;
        CircuitPath::new(entry.clone(), middle, last.clone())
    }

    /// The relay with this identity, if the directory has it.
    pub fn find(&self, node_id: &NodeId) -> Option<&RelayDescriptor> {
        self.relays.iter().find(|d| d.node_id == *node_id)
    }

    /// Random entry and middle, ending at `last`, preferring three different
    /// families and avoiding `unhealthy` relays when possible.
    ///
    /// Entry and middle are chosen together, uniformly among all pairs in
    /// the best available tier: (1) healthy and three distinct families,
    /// (2) healthy, (3) any. Picking them one at a time could take the only
    /// middle that leaves a family-distinct entry.
    pub fn path_avoiding(
        &self,
        last: &RelayDescriptor,
        unhealthy: &[NodeId],
    ) -> Result<CircuitPath, NetError> {
        let missing =
            |role: Role| NetError::InvalidConfig(format!("no {role} relay in the directory"));
        let of_role = |role: Role| -> Vec<&RelayDescriptor> {
            self.relays
                .iter()
                .filter(|d| d.role == role && d.node_id != last.node_id)
                .collect()
        };
        let entries = of_role(Role::Entry);
        let middles = of_role(Role::Middle);
        if entries.is_empty() {
            return Err(missing(Role::Entry));
        }
        if middles.is_empty() {
            return Err(missing(Role::Middle));
        }
        let last_family = last.family_key();
        let pairs: Vec<(&RelayDescriptor, &RelayDescriptor)> = entries
            .iter()
            .flat_map(|e| middles.iter().map(move |m| (*e, *m)))
            .filter(|(e, m)| e.node_id != m.node_id)
            .collect();
        let healthy = |d: &RelayDescriptor| !unhealthy.contains(&d.node_id);
        let healthy_pairs: Vec<_> = pairs
            .iter()
            .copied()
            .filter(|(e, m)| healthy(e) && healthy(m))
            .collect();
        let diverse: Vec<_> = healthy_pairs
            .iter()
            .copied()
            .filter(|(e, m)| {
                let (fe, fm) = (e.family_key(), m.family_key());
                fe != fm
                    && fe != last_family
                    && fm != last_family
                    && !e.related_to(m)
                    && !e.related_to(last)
                    && !m.related_to(last)
            })
            .collect();
        let pool = [diverse, healthy_pairs, pairs]
            .into_iter()
            .find(|pool| !pool.is_empty())
            .ok_or_else(|| missing(Role::Middle))?;
        let index = u64::from_le_bytes(crate::crypto::random_bytes::<8>()) as usize % pool.len();
        let (entry, middle) = pool[index];
        CircuitPath::new(entry.clone(), middle.clone(), last.clone())
    }

    /// Random entry and middle, ending at `last`.
    pub fn path_ending_at(&self, last: &RelayDescriptor) -> Result<CircuitPath, NetError> {
        self.path_avoiding(last, &[])
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

        let mut new_link_key = d.clone();
        new_link_key.link_key = other.link_public();
        assert!(new_link_key.verify().is_err());

        let mut new_family = d.clone();
        new_family.family = "elsewhere".into();
        assert!(new_family.verify().is_err());

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
    fn wire_form_round_trips_and_detects_tampering() {
        let keys = RelayKeys::generate();
        let d = RelayDescriptor::sign_with_family(
            &keys,
            "middle",
            Role::Middle,
            "10.0.0.2:7102".parse().unwrap(),
            "machine-b",
        );
        assert_eq!(RelayDescriptor::from_wire(&d.to_wire()).unwrap(), d);
        let mut bytes = d.to_wire();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert!(RelayDescriptor::from_wire(&bytes).is_err());
    }

    #[test]
    fn invalid_labels_are_refused() {
        let keys = RelayKeys::generate();
        let addr = "127.0.0.1:7101".parse().unwrap();
        assert!(
            RelayDescriptor::sign(&keys, "Entry One", Role::Entry, addr)
                .verify()
                .is_err()
        );
        assert!(
            RelayDescriptor::sign_with_family(&keys, "entry", Role::Entry, addr, "../x")
                .verify()
                .is_err()
        );
        assert!(
            RelayDescriptor::sign(&keys, "entry-1", Role::Entry, addr)
                .verify()
                .is_ok()
        );
    }

    #[test]
    fn paths_prefer_three_families_and_skip_unhealthy_relays() {
        let fam = |role: Role, port: u16, family: &str| {
            RelayDescriptor::sign_with_family(
                &RelayKeys::generate(),
                &format!("{role}{port}"),
                role,
                SocketAddr::from(([127, 0, 0, 1], port)),
                family,
            )
        };
        let rv = fam(Role::Rendezvous, 7104, "a");
        let same_entry = fam(Role::Entry, 7101, "a");
        let other_entry = fam(Role::Entry, 7111, "c");
        let same_middle = fam(Role::Middle, 7102, "a");
        let other_middle = fam(Role::Middle, 7112, "b");
        let directory = Directory::from_descriptors(vec![
            rv.clone(),
            same_entry.clone(),
            other_entry.clone(),
            same_middle,
            other_middle.clone(),
        ])
        .unwrap();
        for _ in 0..20 {
            let path = directory.path_ending_at(&rv).unwrap();
            assert_eq!(path.middle.node_id, other_middle.node_id);
            assert_eq!(path.entry.node_id, other_entry.node_id);
        }
        // The diverse entry is unhealthy: fall back to the other one.
        let path = directory
            .path_avoiding(&rv, &[other_entry.node_id])
            .unwrap();
        assert_eq!(path.entry.node_id, same_entry.node_id);
    }

    #[test]
    fn entry_and_middle_are_chosen_together_for_family_diversity() {
        // The netns layout: entries on m1 and m3, middles on m2 and m3, the
        // last hop on m1. Only entry(m3) + middle(m2) gives three families;
        // choosing the middle first could pick middle(m3) and get stuck.
        let fam = |role: Role, nick: &str, family: &str| {
            RelayDescriptor::sign_with_family(
                &RelayKeys::generate(),
                nick,
                role,
                "127.0.0.1:7000".parse().unwrap(),
                family,
            )
        };
        let rv1 = fam(Role::Rendezvous, "rv1", "m1");
        let entry1 = fam(Role::Entry, "entry1", "m1");
        let entry2 = fam(Role::Entry, "entry2", "m3");
        let middle1 = fam(Role::Middle, "middle1", "m2");
        let middle2 = fam(Role::Middle, "middle2", "m3");
        let directory = Directory::from_descriptors(vec![
            rv1.clone(),
            entry1,
            entry2.clone(),
            middle1.clone(),
            middle2,
        ])
        .unwrap();
        for _ in 0..50 {
            let path = directory.path_ending_at(&rv1).unwrap();
            assert_eq!(path.entry.node_id, entry2.node_id);
            assert_eq!(path.middle.node_id, middle1.node_id);
        }
    }

    #[test]
    fn middles_avoid_the_family_operator_and_network_of_both_ends() {
        let make = |nick: &str, role: Role, addr: &str, family: &str, operator: &str| {
            let mut d = RelayDescriptor::sign_with_family(
                &RelayKeys::generate(),
                nick,
                role,
                addr.parse().unwrap(),
                family,
            );
            d.operator = operator.into();
            d
        };
        let entry = make("entry", Role::Entry, "10.1.0.1:7101", "a", "alice");
        let last = make("rv", Role::Rendezvous, "10.2.0.1:7104", "b", "bob");
        let same_family = make("m-fam", Role::Middle, "10.3.0.1:7102", "a", "carol");
        let same_operator = make("m-op", Role::Middle, "10.4.0.1:7102", "c", "bob");
        let same_network = make("m-net", Role::Middle, "10.1.9.9:7102", "d", "dave");
        let good = make("m-good", Role::Middle, "10.5.0.1:7102", "e", "erin");
        let mut relays = vec![
            entry.clone(),
            last.clone(),
            same_family,
            same_operator,
            same_network.clone(),
            good.clone(),
        ];
        let directory = Directory::from_descriptors(relays.clone()).unwrap();
        for _ in 0..30 {
            let path = directory.path_through(&entry, &last, &[]).unwrap();
            assert_eq!(path.middle.nickname, "m-good");
        }
        // Without it: unrelated beats "same network" being avoided.
        relays.retain(|d| d.nickname != "m-good");
        let directory = Directory::from_descriptors(relays).unwrap();
        for _ in 0..30 {
            let path = directory.path_through(&entry, &last, &[]).unwrap();
            assert_eq!(path.middle.nickname, "m-net");
        }
        assert!(entry.related_to(&make("x", Role::Middle, "10.9.0.1:1", "z", "alice")));
        assert!(!entry.related_to(&good));
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
