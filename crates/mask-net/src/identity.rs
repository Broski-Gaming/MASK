//! Relay identities and roles.
//!
//! In v0.2 a [`NodeId`] is 32 random bytes generated each time a relay
//! starts. It is a label for logging and handshakes, not a cryptographic
//! identity: it proves nothing about who the peer is. A later milestone will
//! replace it with the fingerprint of a long-term public key.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId([u8; 32]);

impl NodeId {
    /// A fresh random ID from the operating system's random number generator.
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).expect("operating system RNG unavailable");
        Self(bytes)
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// First 8 bytes as hex, for log lines.
    pub fn short(&self) -> String {
        hex(&self.0[..8])
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex(&self.0))
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", self.short())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The part a node plays on a route.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    Client,
    Entry,
    Middle,
    Exit,
}

impl Role {
    /// The only role allowed to connect to a relay of this role.
    pub const fn expected_upstream(self) -> Option<Role> {
        match self {
            Role::Entry => Some(Role::Client),
            Role::Middle => Some(Role::Entry),
            Role::Exit => Some(Role::Middle),
            Role::Client => None,
        }
    }

    /// The role this relay must find at its next hop.
    pub const fn expected_downstream(self) -> Option<Role> {
        match self {
            Role::Client => Some(Role::Entry),
            Role::Entry => Some(Role::Middle),
            Role::Middle => Some(Role::Exit),
            Role::Exit => None,
        }
    }

    pub const fn is_relay(self) -> bool {
        !matches!(self, Role::Client)
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Role::Client => "client",
            Role::Entry => "entry",
            Role::Middle => "middle",
            Role::Exit => "exit",
        })
    }
}

impl FromStr for Role {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "entry" => Ok(Role::Entry),
            "middle" => Ok(Role::Middle),
            "exit" => Ok(Role::Exit),
            "client" => Ok(Role::Client),
            other => Err(format!(
                "unknown role \"{other}\" (expected entry, middle, or exit)"
            )),
        }
    }
}

/// Everything a relay says about itself.
#[derive(Clone, Debug)]
pub struct RelayIdentity {
    pub nickname: String,
    pub role: Role,
    pub node_id: NodeId,
}

impl RelayIdentity {
    pub fn generate(nickname: impl Into<String>, role: Role) -> Self {
        Self {
            nickname: nickname.into(),
            role,
            node_id: NodeId::random(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_ids_differ() {
        assert_ne!(NodeId::random(), NodeId::random());
    }

    #[test]
    fn id_formats_as_hex() {
        let id = NodeId::from_bytes([0xab; 32]);
        assert_eq!(id.to_string().len(), 64);
        assert_eq!(id.short(), "abababababababab");
    }

    #[test]
    fn route_order_is_client_entry_middle_exit() {
        assert_eq!(Role::Entry.expected_upstream(), Some(Role::Client));
        assert_eq!(Role::Middle.expected_upstream(), Some(Role::Entry));
        assert_eq!(Role::Exit.expected_upstream(), Some(Role::Middle));
        assert_eq!(Role::Exit.expected_downstream(), None);
        assert_eq!(Role::Client.expected_upstream(), None);
    }

    #[test]
    fn roles_parse_case_insensitively() {
        assert_eq!("Middle".parse::<Role>(), Ok(Role::Middle));
        assert!("guard".parse::<Role>().is_err());
    }
}
