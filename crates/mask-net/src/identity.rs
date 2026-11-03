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
///
/// Circuits always run client → entry → middle → (exit | rendezvous).
/// A **rendezvous**-role relay serves `.morp` hidden services: it can act as
/// an introduction point and as a rendezvous point. Exits only run the echo
/// test service; `.morp` traffic never uses them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Client,
    Entry,
    Middle,
    Exit,
    Rendezvous,
}

impl Role {
    /// The only role allowed to open a link to a relay of this role.
    pub const fn expected_upstream(self) -> Option<Role> {
        match self {
            Role::Entry => Some(Role::Client),
            Role::Middle => Some(Role::Entry),
            Role::Exit | Role::Rendezvous => Some(Role::Middle),
            Role::Client => None,
        }
    }

    /// May a node of this role open a link to (extend a circuit to) `next`?
    pub const fn can_extend_to(self, next: Role) -> bool {
        matches!(
            (self, next),
            (Role::Client, Role::Entry)
                | (Role::Entry, Role::Middle)
                | (Role::Middle, Role::Exit | Role::Rendezvous)
        )
    }

    /// Entry and middle relays extend circuits; the last hop does not.
    pub const fn extends(self) -> bool {
        matches!(self, Role::Entry | Role::Middle)
    }

    /// Roles that may be the last hop of a circuit.
    pub const fn is_last_hop(self) -> bool {
        matches!(self, Role::Exit | Role::Rendezvous)
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
            Role::Rendezvous => "rendezvous",
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
            "rendezvous" => Ok(Role::Rendezvous),
            "client" => Ok(Role::Client),
            other => Err(format!(
                "unknown role \"{other}\" (expected entry, middle, exit, or rendezvous)"
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
        assert_eq!(Role::Rendezvous.expected_upstream(), Some(Role::Middle));
        assert!(Role::Middle.can_extend_to(Role::Exit));
        assert!(Role::Middle.can_extend_to(Role::Rendezvous));
        assert!(!Role::Entry.can_extend_to(Role::Rendezvous));
        assert!(!Role::Rendezvous.extends());
        assert!(!Role::Exit.extends());
    }

    #[test]
    fn roles_parse_case_insensitively() {
        assert_eq!("Middle".parse::<Role>(), Ok(Role::Middle));
        assert!("guard".parse::<Role>().is_err());
    }
}
