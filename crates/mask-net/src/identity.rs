//! Node identifiers and roles.
//!
//! A relay's [`NodeId`] is its Ed25519 identity public key. It is stable for
//! as long as the relay keeps its identity key file (see
//! [`crate::crypto::keys`]). Clients learn node IDs from signed relay
//! descriptors and authenticate each hop against them during the MORP
//! handshake.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Ed25519 identity public key of a relay.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId([u8; 32]);

impl NodeId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// First 8 bytes as hex, for log lines.
    pub fn short(&self) -> String {
        to_hex(&self.0[..8])
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&to_hex(&self.0))
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", self.short())
    }
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn from_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// The part a node plays on a circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    Client,
    Entry,
    Middle,
    Exit,
}

impl Role {
    /// The only role allowed to open a link to a relay of this role.
    pub const fn expected_upstream(self) -> Option<Role> {
        match self {
            Role::Entry => Some(Role::Client),
            Role::Middle => Some(Role::Entry),
            Role::Exit => Some(Role::Middle),
            Role::Client => None,
        }
    }

    /// The role this node's next hop must have.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_formats_as_hex() {
        let id = NodeId::from_bytes([0xab; 32]);
        assert_eq!(id.to_string().len(), 64);
        assert_eq!(id.short(), "abababababababab");
    }

    #[test]
    fn hex_round_trips_and_rejects_bad_input() {
        let bytes = [0x01, 0xfe, 0x7a];
        assert_eq!(from_hex::<3>(&to_hex(&bytes)), Some(bytes));
        assert_eq!(from_hex::<3>("01fe7"), None);
        assert_eq!(from_hex::<3>("01fezz"), None);
    }

    #[test]
    fn route_order_is_client_entry_middle_exit() {
        assert_eq!(Role::Entry.expected_upstream(), Some(Role::Client));
        assert_eq!(Role::Middle.expected_upstream(), Some(Role::Entry));
        assert_eq!(Role::Exit.expected_upstream(), Some(Role::Middle));
        assert_eq!(Role::Exit.expected_downstream(), None);
    }

    #[test]
    fn roles_parse_case_insensitively() {
        assert_eq!("Middle".parse::<Role>(), Ok(Role::Middle));
        assert!("guard".parse::<Role>().is_err());
    }
}
