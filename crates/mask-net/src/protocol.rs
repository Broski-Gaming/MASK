//! MORP wire format. See `docs/MORP.md` for the full description.
//!
//! Two levels:
//!
//! 1. [`LinkMsg`]: what travels on one TCP link between neighbours, one
//!    postcard-encoded message per length-prefixed frame. Visible to anyone
//!    who can observe the link (links are not yet encrypted).
//! 2. [`LayerBody`]: the plaintext of one onion layer, sealed with that hop's
//!    key and carried in `LinkMsg::Relay { cell }`. A hop that opens its
//!    layer finds either another sealed cell to pass along
//!    ([`LayerBody::Relay`]) or a command for itself ([`LayerBody::Cmd`]).

use std::net::SocketAddr;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::crypto::ntor::{CreateReply, CreateRequest};
use crate::identity::Role;

/// MORP protocol version, checked in the link handshake.
pub const MORP_VERSION: u16 = 2;

/// Largest frame accepted on any link.
pub const MAX_FRAME_LEN: usize = 64 * 1024;

/// Largest application payload a client may send in one DATA command,
/// leaving room for three layers of headers and tags inside one frame.
pub const MAX_DATA_LEN: usize = 60 * 1024;

/// Circuit identifier, unique per link. Chosen by the side that opened the
/// link; 0 is reserved.
pub type CircId = u32;

/// Message on one link.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkMsg {
    /// First message from the side opening the link.
    Hello { version: u16, role: Role },
    /// Reply to an acceptable `Hello`.
    Welcome { version: u16, role: Role },
    /// Fatal link-level error, sent just before closing the link.
    LinkError { code: LinkErrorCode, detail: String },

    /// Open circuit `circ` on this link with an ntor handshake.
    Create {
        circ: CircId,
        request: CreateRequest,
    },
    /// Handshake reply for `circ`.
    Created { circ: CircId, reply: CreateReply },
    /// One onion cell on `circ`. Direction is implied by the link: away from
    /// the client on a relay's inbound link, toward it on an outbound link.
    Relay { circ: CircId, cell: Vec<u8> },
    /// Tear down `circ`. Not authenticated (see docs/MORP.md).
    Destroy { circ: CircId, reason: DestroyReason },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkErrorCode {
    VersionMismatch,
    BadHandshake,
    RoleNotAllowed,
    Malformed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DestroyReason {
    /// The client closed the circuit.
    Requested,
    ProtocolViolation,
    /// A cell failed AEAD verification (tampering, replay, or reordering).
    AuthenticationFailed,
    /// CREATE was addressed to a different identity or onion key.
    WrongRelay,
    NextHopFailed,
    Timeout,
    LinkClosed,
    ResourceLimit,
}

/// Plaintext of one onion layer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LayerBody {
    /// A sealed cell for (forward) or from (backward) a hop further along.
    Relay(Vec<u8>),
    /// A command for (forward) or from (backward) this hop.
    Cmd(RelayCmd),
}

/// Commands exchanged end-to-end between the client and one hop.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayCmd {
    /// Client → hop: extend the circuit to `next_hop` with this handshake.
    Extend {
        next_hop: SocketAddr,
        request: CreateRequest,
    },
    /// Hop → client: the next hop's handshake reply.
    Extended { reply: CreateReply },
    /// Application data. In this prototype the exit echoes it back.
    Data { bytes: Vec<u8> },
    /// Hop → client: a command failed. The circuit stays open.
    Error { code: ErrorCode, detail: String },

    // ---- Hidden services (rendezvous-role relays only; see docs/MORP_HIDDEN_SERVICES.md)
    /// Service → intro point: accept introductions for `auth_key`. Signed
    /// by the per-intro auth key (never the service identity key).
    EstablishIntro {
        auth_key: [u8; 32],
        signature: Vec<u8>,
    },
    /// Intro point → service.
    IntroEstablished,
    /// Client → intro point: deliver `payload` (encrypted to the service)
    /// to the service registered under `auth_key`.
    Introduce1 {
        auth_key: [u8; 32],
        payload: Vec<u8>,
    },
    /// Intro point → client: the introduction was forwarded.
    IntroduceAck,
    /// Intro point → service: an introduction from some client.
    Introduce2 { payload: Vec<u8> },
    /// Client → rendezvous point: wait for a service presenting `cookie`.
    EstablishRendezvous { cookie: [u8; 32] },
    /// Rendezvous point → client.
    RendezvousEstablished,
    /// Service → rendezvous point: join me to the circuit waiting with
    /// `cookie`, and pass `payload` (the handshake reply) to it.
    Rendezvous1 { cookie: [u8; 32], payload: Vec<u8> },
    /// Rendezvous point → client: the service's handshake reply.
    Rendezvous2 { payload: Vec<u8> },
    /// End-to-end encrypted data between client and service, passed
    /// unchanged (and unreadable) by the rendezvous point.
    Stream { bytes: Vec<u8> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    /// The hop refused to extend (bad address, or the next hop refused CREATE).
    ExtendRejected,
    NextHopUnreachable,
    /// The command is not allowed at this hop.
    NotAllowed,
    Timeout,
    /// The intro point has no service registered under that auth key.
    UnknownService,
    /// Unknown, expired, or already used rendezvous cookie.
    BadCookie,
    /// A hidden-service request was malformed or badly signed.
    Rejected,
    /// A relay limit was reached.
    ResourceLimit,
}

pub fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    postcard::to_stdvec(value).expect("MORP types always serialize")
}

pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, postcard::Error> {
    postcard::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeId;

    #[test]
    fn link_messages_round_trip() {
        let request = CreateRequest {
            node_id: NodeId::from_bytes([1; 32]),
            onion_key: [2; 32],
            client_public: [3; 32],
        };
        let messages = [
            LinkMsg::Hello {
                version: MORP_VERSION,
                role: Role::Client,
            },
            LinkMsg::Create { circ: 7, request },
            LinkMsg::Relay {
                circ: u32::MAX,
                cell: vec![9; 100],
            },
            LinkMsg::Destroy {
                circ: 1,
                reason: DestroyReason::Timeout,
            },
        ];
        for msg in messages {
            assert_eq!(decode::<LinkMsg>(&encode(&msg)).unwrap(), msg);
        }
    }

    #[test]
    fn layer_bodies_round_trip() {
        let body = LayerBody::Cmd(RelayCmd::Data {
            bytes: b"hi".to_vec(),
        });
        assert_eq!(decode::<LayerBody>(&encode(&body)).unwrap(), body);
    }

    #[test]
    fn garbage_does_not_decode() {
        assert!(decode::<LinkMsg>(&[0xff, 0xff, 0xff]).is_err());
        assert!(decode::<LayerBody>(&[]).is_err());
    }
}
