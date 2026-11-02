//! One-way authenticated key exchange, adapted from Tor's **ntor** handshake
//! (Goldberg, Stebila, Ustaoglu, "Anonymity and one-way authentication in key
//! exchange protocols", 2013; tor-spec §5.1.4).
//!
//! The client knows the relay's identity `ID` (Ed25519 public key) and onion
//! key `B = b·G` (X25519) from the relay's signed descriptor.
//!
//! ```text
//! client:  x random, X = x·G                         ── CREATE(ID, B, X) ──▶
//! relay:   y random, Y = y·G
//!          secret_input = y·X | b·X | ID | B | X | Y | PROTOID
//!          verify, Kf, Kb = HKDF-SHA256(salt=PROTOID, ikm=secret_input)
//!          AUTH = HMAC-SHA256(verify, ID | B | Y | X | PROTOID | "server")
//!                                                     ◀── CREATED(Y, AUTH) ──
//! client:  secret_input = x·Y | x·B | ID | B | X | Y | PROTOID
//!          recompute verify, Kf, Kb; check AUTH in constant time
//! ```
//!
//! Only the holder of `b` can compute `b·X`, so a correct AUTH proves the
//! client is talking to the relay whose descriptor it trusts. The relay
//! learns nothing about who the client is. Fresh `x` and `y` give forward
//! secrecy for the circuit keys once both are erased.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::keys::RelayKeys;
use super::{CryptoError, random_bytes};
use crate::identity::NodeId;

const PROTOID: &[u8] = b"MORP-ntor-x25519-sha256-v1";
const KEY_EXPAND: &[u8] = b"MORP-v1 key expansion";
const SERVER: &[u8] = b"server";

/// Sent by the client in CREATE (directly, or inside EXTEND).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateRequest {
    /// Identity the client expects to reach.
    pub node_id: NodeId,
    /// Onion key from that relay's descriptor.
    pub onion_key: [u8; 32],
    /// Client ephemeral public key `X`.
    pub client_public: [u8; 32],
}

/// Relay's answer in CREATED (directly, or inside EXTENDED).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateReply {
    /// Relay ephemeral public key `Y`.
    pub server_public: [u8; 32],
    pub auth: [u8; 32],
}

/// Symmetric keys shared by the client and one hop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HopKeys {
    /// Client → relay direction.
    pub forward: [u8; 32],
    /// Relay → client direction.
    pub backward: [u8; 32],
}

/// Client state between sending CREATE and receiving CREATED.
pub struct ClientHandshake {
    secret: StaticSecret,
    request: CreateRequest,
}

impl ClientHandshake {
    pub fn start(node_id: NodeId, onion_key: [u8; 32]) -> (Self, CreateRequest) {
        let secret = StaticSecret::from(random_bytes::<32>());
        let request = CreateRequest {
            node_id,
            onion_key,
            client_public: PublicKey::from(&secret).to_bytes(),
        };
        (
            Self {
                secret,
                request: request.clone(),
            },
            request,
        )
    }

    /// Check the relay's reply and derive the hop keys.
    pub fn finish(self, reply: &CreateReply) -> Result<HopKeys, CryptoError> {
        let y_pub = PublicKey::from(reply.server_public);
        let b_pub = PublicKey::from(self.request.onion_key);
        let xy = self.secret.diffie_hellman(&y_pub);
        let xb = self.secret.diffie_hellman(&b_pub);
        if !xy.was_contributory() || !xb.was_contributory() {
            return Err(CryptoError::WeakKey);
        }

        let transcript = Transcript {
            node_id: &self.request.node_id,
            onion_key: &self.request.onion_key,
            client_public: &self.request.client_public,
            server_public: &reply.server_public,
        };
        let (verify, keys) = derive(xy.as_bytes(), xb.as_bytes(), &transcript);
        auth_mac(&verify, &transcript)
            .verify_slice(&reply.auth)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        Ok(keys)
    }
}

/// Relay side: answer a CREATE addressed to `keys`.
pub fn server_respond(
    keys: &RelayKeys,
    request: &CreateRequest,
) -> Result<(CreateReply, HopKeys), CryptoError> {
    if request.node_id != keys.node_id() || request.onion_key != keys.onion_public() {
        return Err(CryptoError::WrongRelay);
    }

    let y = StaticSecret::from(random_bytes::<32>());
    let server_public = PublicKey::from(&y).to_bytes();
    let x_pub = PublicKey::from(request.client_public);
    let yx = y.diffie_hellman(&x_pub);
    let bx = keys.onion_secret().diffie_hellman(&x_pub);
    if !yx.was_contributory() || !bx.was_contributory() {
        return Err(CryptoError::WeakKey);
    }

    let transcript = Transcript {
        node_id: &request.node_id,
        onion_key: &request.onion_key,
        client_public: &request.client_public,
        server_public: &server_public,
    };
    let (verify, hop_keys) = derive(yx.as_bytes(), bx.as_bytes(), &transcript);
    let auth: [u8; 32] = auth_mac(&verify, &transcript)
        .finalize()
        .into_bytes()
        .into();
    Ok((
        CreateReply {
            server_public,
            auth,
        },
        hop_keys,
    ))
}

struct Transcript<'a> {
    node_id: &'a NodeId,
    onion_key: &'a [u8; 32],
    client_public: &'a [u8; 32],
    server_public: &'a [u8; 32],
}

fn derive(
    dh_ephemeral: &[u8; 32],
    dh_onion: &[u8; 32],
    t: &Transcript<'_>,
) -> (Zeroizing<[u8; 32]>, HopKeys) {
    let mut secret_input = Zeroizing::new(Vec::with_capacity(32 * 6 + PROTOID.len()));
    secret_input.extend_from_slice(dh_ephemeral);
    secret_input.extend_from_slice(dh_onion);
    secret_input.extend_from_slice(t.node_id.as_bytes());
    secret_input.extend_from_slice(t.onion_key);
    secret_input.extend_from_slice(t.client_public);
    secret_input.extend_from_slice(t.server_public);
    secret_input.extend_from_slice(PROTOID);

    let hkdf = Hkdf::<Sha256>::new(Some(PROTOID), &secret_input);
    let mut okm = Zeroizing::new([0u8; 96]);
    hkdf.expand(KEY_EXPAND, okm.as_mut())
        .expect("96 bytes is a valid HKDF-SHA256 output length");

    let mut verify = Zeroizing::new([0u8; 32]);
    let mut keys = HopKeys {
        forward: [0; 32],
        backward: [0; 32],
    };
    verify.copy_from_slice(&okm[..32]);
    keys.forward.copy_from_slice(&okm[32..64]);
    keys.backward.copy_from_slice(&okm[64..]);
    (verify, keys)
}

fn auth_mac(verify: &[u8; 32], t: &Transcript<'_>) -> Hmac<Sha256> {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(verify).expect("HMAC accepts 32-byte keys");
    mac.update(t.node_id.as_bytes());
    mac.update(t.onion_key);
    mac.update(t.server_public);
    mac.update(t.client_public);
    mac.update(PROTOID);
    mac.update(SERVER);
    mac
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handshake(relay: &RelayKeys) -> (ClientHandshake, CreateRequest) {
        ClientHandshake::start(relay.node_id(), relay.onion_public())
    }

    #[test]
    fn both_sides_derive_the_same_keys() {
        let relay = RelayKeys::generate();
        let (client, request) = handshake(&relay);
        let (reply, relay_keys) = server_respond(&relay, &request).unwrap();
        let client_keys = client.finish(&reply).unwrap();
        assert_eq!(client_keys.forward, relay_keys.forward);
        assert_eq!(client_keys.backward, relay_keys.backward);
        assert_ne!(client_keys.forward, client_keys.backward);
    }

    #[test]
    fn each_handshake_gives_fresh_keys() {
        let relay = RelayKeys::generate();
        let (_, request_a) = handshake(&relay);
        let (_, request_b) = handshake(&relay);
        let (_, a) = server_respond(&relay, &request_a).unwrap();
        let (_, b) = server_respond(&relay, &request_b).unwrap();
        assert_ne!(a.forward, b.forward);
    }

    #[test]
    fn relay_rejects_request_for_another_identity_or_onion_key() {
        let relay = RelayKeys::generate();
        let other = RelayKeys::generate();
        let (_, request) = handshake(&other);
        assert_eq!(
            server_respond(&relay, &request).err(),
            Some(CryptoError::WrongRelay)
        );

        let (_, mut stale) = handshake(&relay);
        stale.onion_key = other.onion_public();
        assert_eq!(
            server_respond(&relay, &stale).err(),
            Some(CryptoError::WrongRelay)
        );
    }

    #[test]
    fn impostor_without_onion_secret_fails_authentication() {
        // The impostor claims `real`'s identity and onion key but only holds
        // its own secrets, so it cannot compute b·X.
        let real = RelayKeys::generate();
        let impostor = RelayKeys::generate();
        let (client, request) = handshake(&real);
        let forged = CreateRequest {
            node_id: impostor.node_id(),
            onion_key: impostor.onion_public(),
            ..request
        };
        let (reply, _) = server_respond(&impostor, &forged).unwrap();
        assert_eq!(
            client.finish(&reply).err(),
            Some(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn tampered_reply_is_rejected() {
        let relay = RelayKeys::generate();

        let (client, request) = handshake(&relay);
        let (mut reply, _) = server_respond(&relay, &request).unwrap();
        reply.auth[0] ^= 1;
        assert_eq!(
            client.finish(&reply).err(),
            Some(CryptoError::AuthenticationFailed)
        );

        let (client, request) = handshake(&relay);
        let (mut reply, _) = server_respond(&relay, &request).unwrap();
        reply.server_public[5] ^= 1;
        assert!(client.finish(&reply).is_err());
    }

    #[test]
    fn low_order_public_keys_are_rejected() {
        let relay = RelayKeys::generate();
        let (_, mut request) = handshake(&relay);
        request.client_public = [0; 32];
        assert_eq!(
            server_respond(&relay, &request).err(),
            Some(CryptoError::WeakKey)
        );

        let (client, _) = handshake(&relay);
        let reply = CreateReply {
            server_public: [0; 32],
            auth: [0; 32],
        };
        assert_eq!(client.finish(&reply).err(), Some(CryptoError::WeakKey));
    }
}
