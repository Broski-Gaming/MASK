//! Wire protocol.
//!
//! Two levels, deliberately kept apart so encryption can slot in between:
//!
//! 1. [`Message`] is what travels on a TCP link between two neighbours
//!    (client ↔ entry, entry ↔ middle, middle ↔ exit). Each message is
//!    one length-prefixed frame (see [`crate::transport`]).
//! 2. [`OnionLayer`] is the per-hop instruction carried *inside*
//!    `Message::Relay { payload }`. The client builds one layer per relay,
//!    nested: the entry's layer contains the middle's, which contains the
//!    exit's. Each relay peels exactly one layer.
//!
//! Today `payload` is a plain postcard-encoded `OnionLayer`, so every relay
//! can read it. **Next milestone:** each layer becomes ciphertext encrypted to
//! that hop's key; a relay decrypts its layer, learns only the next hop, and
//! forwards the still-encrypted rest. Responses travel back the same path and
//! gain one encryption layer per hop. The `Message` level does not change.

use std::fmt;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::identity::{NodeId, Role};

/// Bumped whenever the wire format changes incompatibly.
pub const PROTOCOL_VERSION: u16 = 1;

/// Largest frame accepted on any link. Bounds memory used per message.
pub const MAX_FRAME_LEN: usize = 64 * 1024;

/// A message on one link between neighbouring nodes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Message {
    /// First message from the connecting side.
    Hello {
        version: u16,
        role: Role,
        node_id: NodeId,
    },
    /// Relay's reply to an acceptable `Hello`.
    Welcome {
        version: u16,
        role: Role,
        node_id: NodeId,
    },
    /// Onion payload travelling away from the client.
    Relay { payload: Vec<u8> },
    /// Reply payload travelling back toward the client.
    RelayResponse { payload: Vec<u8> },
    /// Something went wrong at this hop or further along the route.
    Error { code: ErrorCode, detail: String },
}

/// One relay's instruction, peeled from `Message::Relay { payload }`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OnionLayer {
    /// Send `inner` to the relay at `next_hop`.
    Forward {
        next_hop: SocketAddr,
        inner: Vec<u8>,
    },
    /// Final layer, for the exit: hand `data` to the exit service.
    Deliver { data: Vec<u8> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    VersionMismatch,
    BadHandshake,
    RoleNotAllowed,
    MalformedMessage,
    MalformedLayer,
    LayerNotAllowed,
    NextHopRejected,
    NextHopUnreachable,
    Timeout,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl Message {
    pub fn encode(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_stdvec(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(bytes)
    }
}

impl OnionLayer {
    pub fn encode(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_stdvec(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_round_trip() {
        let messages = [
            Message::Hello {
                version: PROTOCOL_VERSION,
                role: Role::Client,
                node_id: NodeId::from_bytes([7; 32]),
            },
            Message::Relay {
                payload: vec![1, 2, 3],
            },
            Message::Error {
                code: ErrorCode::Timeout,
                detail: "slow".into(),
            },
        ];
        for msg in messages {
            assert_eq!(Message::decode(&msg.encode().unwrap()).unwrap(), msg);
        }
    }

    #[test]
    fn layers_round_trip() {
        let layer = OnionLayer::Forward {
            next_hop: "127.0.0.1:7102".parse().unwrap(),
            inner: b"inner".to_vec(),
        };
        assert_eq!(OnionLayer::decode(&layer.encode().unwrap()).unwrap(), layer);
    }

    #[test]
    fn garbage_does_not_decode() {
        assert!(Message::decode(&[0xff, 0xff, 0xff]).is_err());
        assert!(OnionLayer::decode(&[]).is_err());
    }
}
