//! Configuration files (TOML) for a MORP testnet.
//!
//! - `network.toml`: the **trust anchor** shared by every machine: network
//!   name, scope, and each directory authority's address and pinned keys.
//!   Copy it to each machine yourself; never download it.
//! - `relay.toml`: one relay (nickname, role, listen/advertise, family).
//! - `authority.toml`: one directory authority.
//! - `approved-relays.toml`: the authority's allowlist (nickname → identity
//!   and role). Only these relays are listed in the consensus.
//!
//! Unknown keys are errors (catches typos). Relative paths inside a file are
//! resolved against that file's folder. Examples: `deploy/`.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::NetError;
use crate::descriptor::{MAX_FAMILY_LEN, MAX_NICKNAME_LEN, valid_label};
use crate::identity::{NodeId, Role, from_hex};
use crate::scope::NetworkScope;

fn invalid(path: &Path, why: impl std::fmt::Display) -> NetError {
    NetError::InvalidConfig(format!("{}: {why}", path.display()))
}

fn read_toml<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, NetError> {
    let text = std::fs::read_to_string(path).map_err(|e| invalid(path, e))?;
    toml::from_str(&text).map_err(|e| invalid(path, e))
}

/// Resolve `p` relative to the folder containing `file`.
fn relative_to(file: &Path, p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_owned()
    } else {
        file.parent().unwrap_or(Path::new(".")).join(p)
    }
}

fn hex32(path: &Path, field: &str, value: &str) -> Result<[u8; 32], NetError> {
    from_hex::<32>(value.trim())
        .ok_or_else(|| invalid(path, format!("{field} must be 64 hexadecimal characters")))
}

fn check_label(
    path: &Path,
    what: &str,
    label: &str,
    max: usize,
    allow_empty: bool,
) -> Result<(), NetError> {
    if (!allow_empty && label.is_empty()) || !valid_label(label, max) {
        return Err(invalid(
            path,
            format!("{what} \"{label}\" must be 1-{max} characters of a-z, 0-9, - and _"),
        ));
    }
    Ok(())
}

// ------------------------------------------------------------ network.toml

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkFile {
    name: String,
    scope: NetworkScope,
    #[serde(rename = "authority")]
    authorities: Vec<AuthorityEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityEntry {
    name: String,
    address: SocketAddr,
    identity: String,
    link_key: String,
}

/// A directory authority as pinned in `network.toml`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityInfo {
    pub name: String,
    pub address: SocketAddr,
    /// Ed25519 key that signs consensus documents.
    pub identity: [u8; 32],
    /// X25519 Noise link key.
    pub link_key: [u8; 32],
}

/// The trust anchor of a MORP network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkConfig {
    pub name: String,
    pub scope: NetworkScope,
    pub authorities: Vec<AuthorityInfo>,
}

impl NetworkConfig {
    pub fn load(path: &Path) -> Result<Self, NetError> {
        let file: NetworkFile = read_toml(path)?;
        check_label(path, "network name", &file.name, 32, false)?;
        if file.authorities.is_empty() {
            return Err(invalid(path, "at least one [[authority]] is required"));
        }
        let mut authorities = Vec::new();
        let mut seen = HashSet::new();
        for a in file.authorities {
            check_label(path, "authority name", &a.name, MAX_NICKNAME_LEN, false)?;
            file.scope
                .check_reachable(a.address)
                .map_err(|e| invalid(path, format!("authority {}: {e}", a.name)))?;
            let info = AuthorityInfo {
                identity: hex32(path, "identity", &a.identity)?,
                link_key: hex32(path, "link_key", &a.link_key)?,
                name: a.name,
                address: a.address,
            };
            if !seen.insert(info.identity) {
                return Err(invalid(path, "two authorities share an identity key"));
            }
            authorities.push(info);
        }
        Ok(Self {
            name: file.name,
            scope: file.scope,
            authorities,
        })
    }

    pub fn authority_by_identity(&self, identity: &[u8; 32]) -> Option<&AuthorityInfo> {
        self.authorities.iter().find(|a| a.identity == *identity)
    }
}

// -------------------------------------------------------------- relay.toml

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayFile {
    nickname: String,
    role: Role,
    listen: SocketAddr,
    advertise: Option<SocketAddr>,
    #[serde(default)]
    family: String,
    data_dir: Option<PathBuf>,
    network: PathBuf,
    #[serde(default = "default_refresh")]
    consensus_refresh_secs: u64,
    #[serde(default = "default_keepalive")]
    keepalive_secs: u64,
    #[serde(default)]
    limits: LimitsFile,
}

fn default_keepalive() -> u64 {
    30
}

fn default_refresh() -> u64 {
    30
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsFile {
    max_links: Option<usize>,
    max_links_per_ip: Option<usize>,
    max_circuits: Option<usize>,
    max_circuits_per_link: Option<usize>,
}

/// Parsed `relay.toml`.
#[derive(Clone, Debug)]
pub struct RelayFileConfig {
    pub nickname: String,
    pub role: Role,
    pub listen: SocketAddr,
    pub advertise: Option<SocketAddr>,
    pub family: String,
    pub data_dir: PathBuf,
    pub network_path: PathBuf,
    pub network: NetworkConfig,
    /// How often the relay fetches the consensus (2-3600 s).
    pub consensus_refresh_secs: u64,
    /// Keepalive interval for links to other relays (1-600 s). A next hop
    /// that stays silent for about three intervals is declared dead.
    pub keepalive_secs: u64,
    pub max_links: Option<usize>,
    pub max_links_per_ip: Option<usize>,
    pub max_circuits: Option<usize>,
    pub max_circuits_per_link: Option<usize>,
}

impl RelayFileConfig {
    pub fn load(path: &Path) -> Result<Self, NetError> {
        let file: RelayFile = read_toml(path)?;
        check_label(path, "nickname", &file.nickname, MAX_NICKNAME_LEN, false)?;
        check_label(path, "family", &file.family, MAX_FAMILY_LEN, true)?;
        if !file.role.is_relay() {
            return Err(invalid(
                path,
                "role must be entry, middle, exit, or rendezvous",
            ));
        }
        let network_path = relative_to(path, &file.network);
        let network = NetworkConfig::load(&network_path)?;
        network
            .scope
            .check(file.listen)
            .map_err(|e| invalid(path, format!("listen: {e}")))?;
        if let Some(advertise) = file.advertise {
            network
                .scope
                .check_reachable(advertise)
                .map_err(|e| invalid(path, format!("advertise: {e}")))?;
        } else if file.listen.port() == 0 {
            return Err(invalid(
                path,
                "listen needs a fixed port (or set advertise)",
            ));
        }
        if !(2..=3600).contains(&file.consensus_refresh_secs) {
            return Err(invalid(path, "consensus_refresh_secs must be 2-3600"));
        }
        if !(1..=600).contains(&file.keepalive_secs) {
            return Err(invalid(path, "keepalive_secs must be 1-600"));
        }
        let data_dir = relative_to(
            path,
            &file
                .data_dir
                .unwrap_or_else(|| PathBuf::from(format!("relays/{}", file.nickname))),
        );
        Ok(Self {
            nickname: file.nickname,
            role: file.role,
            listen: file.listen,
            advertise: file.advertise,
            family: file.family,
            data_dir,
            network_path,
            network,
            consensus_refresh_secs: file.consensus_refresh_secs,
            keepalive_secs: file.keepalive_secs,
            max_links: file.limits.max_links,
            max_links_per_ip: file.limits.max_links_per_ip,
            max_circuits: file.limits.max_circuits,
            max_circuits_per_link: file.limits.max_circuits_per_link,
        })
    }
}

// ---------------------------------------------------------- authority.toml

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityFile {
    name: String,
    listen: SocketAddr,
    data_dir: Option<PathBuf>,
    network: PathBuf,
    approved_relays: PathBuf,
    #[serde(default = "default_interval")]
    consensus_interval_secs: u64,
    #[serde(default = "default_lifetime")]
    consensus_lifetime_secs: u64,
    #[serde(default = "default_probe")]
    probe_interval_secs: u64,
}

fn default_interval() -> u64 {
    60
}
fn default_lifetime() -> u64 {
    600
}
fn default_probe() -> u64 {
    20
}

/// Parsed `authority.toml`.
#[derive(Clone, Debug)]
pub struct AuthorityFileConfig {
    pub name: String,
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    pub network: NetworkConfig,
    pub approved_relays_path: PathBuf,
    pub consensus_interval_secs: u64,
    pub consensus_lifetime_secs: u64,
    pub probe_interval_secs: u64,
}

impl AuthorityFileConfig {
    pub fn load(path: &Path) -> Result<Self, NetError> {
        let file: AuthorityFile = read_toml(path)?;
        check_label(path, "name", &file.name, MAX_NICKNAME_LEN, false)?;
        let network = NetworkConfig::load(&relative_to(path, &file.network))?;
        network
            .scope
            .check(file.listen)
            .map_err(|e| invalid(path, format!("listen: {e}")))?;
        if !network.authorities.iter().any(|a| a.name == file.name) {
            return Err(invalid(
                path,
                format!("network.toml has no [[authority]] named \"{}\"", file.name),
            ));
        }
        if !(10..=3600).contains(&file.consensus_interval_secs)
            || file.consensus_lifetime_secs < 2 * file.consensus_interval_secs
            || file.consensus_lifetime_secs > 86_400
            || !(2..=3600).contains(&file.probe_interval_secs)
        {
            return Err(invalid(
                path,
                "need 10 <= consensus_interval_secs <= 3600, 2*interval <= consensus_lifetime_secs <= 86400, 2 <= probe_interval_secs <= 3600",
            ));
        }
        Ok(Self {
            data_dir: relative_to(
                path,
                &file
                    .data_dir
                    .unwrap_or_else(|| PathBuf::from(format!("authorities/{}", file.name))),
            ),
            approved_relays_path: relative_to(path, &file.approved_relays),
            name: file.name,
            listen: file.listen,
            network,
            consensus_interval_secs: file.consensus_interval_secs,
            consensus_lifetime_secs: file.consensus_lifetime_secs,
            probe_interval_secs: file.probe_interval_secs,
        })
    }
}

// ---------------------------------------------------- approved-relays.toml

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedFile {
    #[serde(default, rename = "relay")]
    relays: Vec<ApprovedEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedEntry {
    nickname: String,
    identity: String,
    role: Role,
}

/// One allowlisted relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovedRelay {
    pub nickname: String,
    pub identity: NodeId,
    pub role: Role,
}

/// The authority's relay allowlist. Each nickname is bound to exactly one
/// identity, so a relay cannot change its identity without the operator
/// editing this file.
#[derive(Clone, Debug, Default)]
pub struct ApprovedRelays {
    pub relays: Vec<ApprovedRelay>,
}

impl ApprovedRelays {
    pub fn load(path: &Path) -> Result<Self, NetError> {
        let file: ApprovedFile = read_toml(path)?;
        let mut relays = Vec::new();
        let mut nicknames = HashSet::new();
        let mut identities = HashSet::new();
        for r in file.relays {
            check_label(path, "nickname", &r.nickname, MAX_NICKNAME_LEN, false)?;
            if !r.role.is_relay() {
                return Err(invalid(
                    path,
                    format!("{}: role must be a relay role", r.nickname),
                ));
            }
            let identity = NodeId::from_bytes(hex32(path, "identity", &r.identity)?);
            if !nicknames.insert(r.nickname.clone()) || !identities.insert(identity) {
                return Err(invalid(
                    path,
                    format!("{}: each nickname and identity may appear once", r.nickname),
                ));
            }
            relays.push(ApprovedRelay {
                nickname: r.nickname,
                identity,
                role: r.role,
            });
        }
        Ok(Self { relays })
    }

    pub fn by_nickname(&self, nickname: &str) -> Option<&ApprovedRelay> {
        self.relays.iter().find(|r| r.nickname == nickname)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const KEY_A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const KEY_B: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn network(dir: &Path, scope: &str, address: &str) -> PathBuf {
        let path = dir.join("network.toml");
        fs::write(
            &path,
            format!(
                "name = \"mask-lan\"\nscope = \"{scope}\"\n\n[[authority]]\nname = \"auth1\"\n\
                 address = \"{address}\"\nidentity = \"{KEY_A}\"\nlink_key = \"{KEY_B}\"\n"
            ),
        )
        .unwrap();
        path
    }

    #[test]
    fn network_file_parses() {
        let dir = tempfile::tempdir().unwrap();
        let config =
            NetworkConfig::load(&network(dir.path(), "private", "192.168.1.10:7300")).unwrap();
        assert_eq!(config.name, "mask-lan");
        assert_eq!(config.scope, NetworkScope::Private);
        assert_eq!(config.authorities[0].identity, [0x11; 32]);
    }

    #[test]
    fn network_file_refuses_public_and_out_of_scope_authorities() {
        let dir = tempfile::tempdir().unwrap();
        assert!(NetworkConfig::load(&network(dir.path(), "private", "8.8.8.8:7300")).is_err());
        assert!(
            NetworkConfig::load(&network(dir.path(), "loopback", "192.168.1.10:7300")).is_err()
        );
        assert!(NetworkConfig::load(&network(dir.path(), "public", "8.8.8.8:7300")).is_err());
    }

    #[test]
    fn relay_file_parses_resolves_paths_and_checks_scope() {
        let dir = tempfile::tempdir().unwrap();
        network(dir.path(), "private", "10.0.0.1:7300");
        let relay = dir.path().join("relay.toml");
        fs::write(
            &relay,
            "nickname = \"entry1\"\nrole = \"entry\"\nlisten = \"10.0.0.2:7101\"\n\
             family = \"machine-b\"\nnetwork = \"network.toml\"\n[limits]\nmax_links = 100\n",
        )
        .unwrap();
        let config = RelayFileConfig::load(&relay).unwrap();
        assert_eq!(config.role, Role::Entry);
        assert_eq!(config.data_dir, dir.path().join("relays/entry1"));
        assert_eq!(config.max_links, Some(100));

        for bad in [
            "listen = \"8.8.8.8:7101\"", // public
            "listen = \"0.0.0.0:7101\"", // every interface
            "listen = \"10.0.0.2:0\"",   // no fixed port
        ] {
            fs::write(
                &relay,
                format!(
                    "nickname = \"entry1\"\nrole = \"entry\"\n{bad}\nnetwork = \"network.toml\"\n"
                ),
            )
            .unwrap();
            assert!(RelayFileConfig::load(&relay).is_err(), "{bad}");
        }
    }

    #[test]
    fn unknown_keys_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        network(dir.path(), "private", "10.0.0.1:7300");
        let relay = dir.path().join("relay.toml");
        fs::write(
            &relay,
            "nickname = \"e\"\nrole = \"entry\"\nlisten = \"10.0.0.2:7101\"\nnetwork = \"network.toml\"\nencryption = false\n",
        )
        .unwrap();
        assert!(RelayFileConfig::load(&relay).is_err());
    }

    #[test]
    fn allowlist_binds_each_nickname_to_one_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approved-relays.toml");
        fs::write(
            &path,
            format!(
                "[[relay]]\nnickname = \"entry1\"\nidentity = \"{KEY_A}\"\nrole = \"entry\"\n\
                 [[relay]]\nnickname = \"middle1\"\nidentity = \"{KEY_B}\"\nrole = \"middle\"\n"
            ),
        )
        .unwrap();
        let approved = ApprovedRelays::load(&path).unwrap();
        assert_eq!(approved.by_nickname("middle1").unwrap().role, Role::Middle);

        fs::write(
            &path,
            format!(
                "[[relay]]\nnickname = \"entry1\"\nidentity = \"{KEY_A}\"\nrole = \"entry\"\n\
                 [[relay]]\nnickname = \"entry1\"\nidentity = \"{KEY_B}\"\nrole = \"entry\"\n"
            ),
        )
        .unwrap();
        assert!(ApprovedRelays::load(&path).is_err());
    }

    #[test]
    fn deploy_examples_parse_once_placeholders_are_filled_in() {
        let deploy = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy");
        let dir = tempfile::tempdir().unwrap();
        let mut n = 0u8;
        for entry in fs::read_dir(&deploy).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|e| e != "toml") {
                continue;
            }
            let mut text = fs::read_to_string(&path).unwrap();
            // Each placeholder becomes a distinct key.
            while let Some(start) = text.find("REPLACE_WITH") {
                let end = start + text[start..].find('"').unwrap();
                n += 1;
                text.replace_range(start..end, &format!("{n:02x}").repeat(32));
            }
            fs::write(dir.path().join(path.file_name().unwrap()), text).unwrap();
        }
        let d = dir.path();
        let network = NetworkConfig::load(&d.join("network.toml")).unwrap();
        assert_eq!(network.scope, NetworkScope::Private);
        AuthorityFileConfig::load(&d.join("authority.toml")).unwrap();
        assert_eq!(
            ApprovedRelays::load(&d.join("approved-relays.toml"))
                .unwrap()
                .relays
                .len(),
            6
        );
        for relay in ["relay-entry1.toml", "relay-middle1.toml", "relay-rv2.toml"] {
            RelayFileConfig::load(&d.join(relay)).unwrap();
        }
    }
}
