//! Hidden-service cryptography. Established primitives only: Ed25519,
//! X25519, HKDF-SHA256, ChaCha20-Poly1305. The structure follows Tor v3
//! onion services (per-intro auth keys, introduction payload encrypted to a
//! per-intro encryption key, service authenticated at the rendezvous).
//!
//! ```text
//! Intro point setup (service → intro point, inside the service's circuit):
//!   auth = fresh Ed25519 key per intro point     (NOT the identity key)
//!   EstablishIntro { auth_pub, Sign(auth, D_EST || intro_node_id || auth_pub) }
//!
//! Introduction (client → intro point → service):
//!   client: x random, X = x·G,  cookie = 32 random bytes
//!   k_intro = HKDF(salt = D_INTRO, ikm = x·ENC, info = service_key || auth_pub || ENC || X)
//!   Introduce1 { auth_pub, X || AEAD(k_intro, {rendezvous relay, cookie}) }
//!   (ENC = the service's per-intro X25519 encryption key from its descriptor)
//!
//! Rendezvous (service → rendezvous point → client):
//!   service: y random, Y = y·G
//!   sig = Sign(identity, D_E2E || service_key || X || Y || cookie)
//!   Rendezvous1 { cookie, Y || sig }  →  Rendezvous2 { Y || sig }
//!   client: verify sig with the public key inside the .morp address
//!   c2s || s2c = HKDF(salt = D_E2E, ikm = y·X = x·Y,
//!                     info = KEYS || service_key || X || Y || cookie)
//! ```
//!
//! The intro point sees only `auth_pub` and ciphertext; the rendezvous point
//! sees only the cookie, `Y`, the signature, and then ciphertext.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::address::MorpAddress;
use crate::crypto::onion::{CellCipher, Direction};
use crate::crypto::{CryptoError, random_bytes};
use crate::identity::NodeId;
use crate::protocol::{decode, encode};
use crate::service::keys::ServiceKeys;

const D_EST: &[u8] = b"MORP-v1 establish intro\0";
const D_INTRO: &[u8] = b"MORP-v1 introduce\0";
const D_E2E: &[u8] = b"MORP-v1 hidden service e2e\0";
const KEY_INFO: &[u8] = b"MORP-v1 e2e keys";

pub const INTRO_VERSION: u16 = 1;

// ------------------------------------------------------------ intro keys

/// Keys a service uses for one introduction point. Generated fresh each
/// time the service starts; only the public halves leave the service.
pub struct IntroKeys {
    auth: SigningKey,
    enc: StaticSecret,
}

impl IntroKeys {
    pub fn generate() -> Self {
        let seed = Zeroizing::new(random_bytes::<32>());
        Self {
            auth: SigningKey::from_bytes(&seed),
            enc: StaticSecret::from(random_bytes::<32>()),
        }
    }

    pub fn auth_public(&self) -> [u8; 32] {
        self.auth.verifying_key().to_bytes()
    }

    pub fn enc_public(&self) -> [u8; 32] {
        PublicKey::from(&self.enc).to_bytes()
    }

    /// Signature for `EstablishIntro` at the relay `intro_node`.
    pub fn establish_signature(&self, intro_node: &NodeId) -> Vec<u8> {
        self.auth
            .sign(&establish_message(&self.auth_public(), intro_node))
            .to_bytes()
            .to_vec()
    }
}

fn establish_message(auth_key: &[u8; 32], intro_node: &NodeId) -> Vec<u8> {
    let mut msg = D_EST.to_vec();
    msg.extend_from_slice(intro_node.as_bytes());
    msg.extend_from_slice(auth_key);
    msg
}

/// Intro point side: check that `EstablishIntro` was signed by `auth_key`
/// for this relay.
pub fn verify_establish_intro(
    auth_key: &[u8; 32],
    intro_node: &NodeId,
    signature: &[u8],
) -> Result<(), CryptoError> {
    let key = VerifyingKey::from_bytes(auth_key).map_err(|_| CryptoError::BadSignature)?;
    if key.is_weak() {
        return Err(CryptoError::BadSignature);
    }
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| CryptoError::BadSignature)?;
    key.verify_strict(
        &establish_message(auth_key, intro_node),
        &Signature::from_bytes(&signature),
    )
    .map_err(|_| CryptoError::BadSignature)
}

// ----------------------------------------------------------- introduction

/// What the client tells the service, encrypted to the service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntroPlaintext {
    pub version: u16,
    /// The rendezvous relay the service must connect to.
    pub rendezvous: NodeId,
    pub cookie: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct IntroEnvelope {
    client_ephemeral: [u8; 32],
    ciphertext: Vec<u8>,
}

/// A decrypted introduction, as seen by the service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Introduction {
    pub client_ephemeral: [u8; 32],
    pub rendezvous: NodeId,
    pub cookie: [u8; 32],
}

/// Client state between sending `Introduce1` and receiving `Rendezvous2`.
pub struct ClientIntro {
    secret: StaticSecret,
    client_ephemeral: [u8; 32],
    cookie: [u8; 32],
    service: MorpAddress,
}

fn intro_key(
    shared: &[u8; 32],
    service: &MorpAddress,
    auth_key: &[u8; 32],
    enc_key: &[u8; 32],
    client_ephemeral: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    let mut info = service.public_key().to_vec();
    info.extend_from_slice(auth_key);
    info.extend_from_slice(enc_key);
    info.extend_from_slice(client_ephemeral);
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(D_INTRO), shared)
        .expand(&info, key.as_mut())
        .expect("32 bytes is a valid HKDF output length");
    key
}

impl ClientIntro {
    /// Build the encrypted `Introduce1` payload for one intro point.
    pub fn new(
        service: MorpAddress,
        auth_key: &[u8; 32],
        enc_key: &[u8; 32],
        rendezvous: NodeId,
        cookie: [u8; 32],
    ) -> Result<(Self, Vec<u8>), CryptoError> {
        let secret = StaticSecret::from(random_bytes::<32>());
        let client_ephemeral = PublicKey::from(&secret).to_bytes();
        let shared = secret.diffie_hellman(&PublicKey::from(*enc_key));
        if !shared.was_contributory() {
            return Err(CryptoError::WeakKey);
        }
        let key = intro_key(
            shared.as_bytes(),
            &service,
            auth_key,
            enc_key,
            &client_ephemeral,
        );
        let plaintext = IntroPlaintext {
            version: INTRO_VERSION,
            rendezvous,
            cookie,
        };
        let ciphertext = CellCipher::new(&key, Direction::Forward).seal(&encode(&plaintext))?;
        let envelope = encode(&IntroEnvelope {
            client_ephemeral,
            ciphertext,
        });
        Ok((
            Self {
                secret,
                client_ephemeral,
                cookie,
                service,
            },
            envelope,
        ))
    }

    /// Check the service's signed reply and derive the session keys.
    pub fn finish(self, reply: &[u8]) -> Result<SessionKeys, CryptoError> {
        let reply: RendezvousReply =
            decode(reply).map_err(|_| CryptoError::AuthenticationFailed)?;
        let signature: [u8; 64] = reply
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::BadSignature)?;
        self.service
            .verifying_key()
            .verify_strict(
                &e2e_transcript(
                    &self.service,
                    &self.client_ephemeral,
                    &reply.server_ephemeral,
                    &self.cookie,
                ),
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| CryptoError::BadSignature)?;
        let shared = self
            .secret
            .diffie_hellman(&PublicKey::from(reply.server_ephemeral));
        if !shared.was_contributory() {
            return Err(CryptoError::WeakKey);
        }
        Ok(session_keys(
            shared.as_bytes(),
            &self.service,
            &self.client_ephemeral,
            &reply.server_ephemeral,
            &self.cookie,
        ))
    }

    pub fn cookie(&self) -> [u8; 32] {
        self.cookie
    }
}

/// Service side: decrypt an `Introduce2` payload.
pub fn open_introduction(
    service: &MorpAddress,
    intro: &IntroKeys,
    payload: &[u8],
) -> Result<Introduction, CryptoError> {
    let envelope: IntroEnvelope = decode(payload).map_err(|_| CryptoError::AuthenticationFailed)?;
    let shared = intro
        .enc
        .diffie_hellman(&PublicKey::from(envelope.client_ephemeral));
    if !shared.was_contributory() {
        return Err(CryptoError::WeakKey);
    }
    let key = intro_key(
        shared.as_bytes(),
        service,
        &intro.auth_public(),
        &intro.enc_public(),
        &envelope.client_ephemeral,
    );
    let plaintext = CellCipher::new(&key, Direction::Forward).open(&envelope.ciphertext)?;
    let inner: IntroPlaintext =
        decode(&plaintext).map_err(|_| CryptoError::AuthenticationFailed)?;
    if inner.version != INTRO_VERSION {
        return Err(CryptoError::AuthenticationFailed);
    }
    Ok(Introduction {
        client_ephemeral: envelope.client_ephemeral,
        rendezvous: inner.rendezvous,
        cookie: inner.cookie,
    })
}

// ------------------------------------------------------------ rendezvous

#[derive(Serialize, Deserialize)]
struct RendezvousReply {
    server_ephemeral: [u8; 32],
    signature: Vec<u8>,
}

fn e2e_transcript(
    service: &MorpAddress,
    client: &[u8; 32],
    server: &[u8; 32],
    cookie: &[u8; 32],
) -> Vec<u8> {
    let mut t = D_E2E.to_vec();
    t.extend_from_slice(service.public_key());
    t.extend_from_slice(client);
    t.extend_from_slice(server);
    t.extend_from_slice(cookie);
    t
}

/// End-to-end session keys between client and service.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    pub client_to_service: [u8; 32],
    pub service_to_client: [u8; 32],
}

fn session_keys(
    shared: &[u8; 32],
    service: &MorpAddress,
    client: &[u8; 32],
    server: &[u8; 32],
    cookie: &[u8; 32],
) -> SessionKeys {
    let mut info = KEY_INFO.to_vec();
    info.extend_from_slice(service.public_key());
    info.extend_from_slice(client);
    info.extend_from_slice(server);
    info.extend_from_slice(cookie);
    let mut okm = Zeroizing::new([0u8; 64]);
    Hkdf::<Sha256>::new(Some(D_E2E), shared)
        .expand(&info, okm.as_mut())
        .expect("64 bytes is a valid HKDF output length");
    let mut keys = SessionKeys {
        client_to_service: [0; 32],
        service_to_client: [0; 32],
    };
    keys.client_to_service.copy_from_slice(&okm[..32]);
    keys.service_to_client.copy_from_slice(&okm[32..]);
    keys
}

/// Service side: answer an introduction. Returns the `Rendezvous1` payload
/// and the session keys.
pub fn accept_introduction(
    identity: &ServiceKeys,
    intro: &Introduction,
) -> Result<(Vec<u8>, SessionKeys), CryptoError> {
    let y = StaticSecret::from(random_bytes::<32>());
    let server_ephemeral = PublicKey::from(&y).to_bytes();
    let shared = y.diffie_hellman(&PublicKey::from(intro.client_ephemeral));
    if !shared.was_contributory() {
        return Err(CryptoError::WeakKey);
    }
    let address = identity.address();
    let signature = identity.sign(&e2e_transcript(
        address,
        &intro.client_ephemeral,
        &server_ephemeral,
        &intro.cookie,
    ));
    let keys = session_keys(
        shared.as_bytes(),
        address,
        &intro.client_ephemeral,
        &server_ephemeral,
        &intro.cookie,
    );
    let reply = encode(&RendezvousReply {
        server_ephemeral,
        signature: signature.to_vec(),
    });
    Ok((reply, keys))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node() -> NodeId {
        NodeId::from_bytes([9; 32])
    }

    #[test]
    fn establish_intro_signature_is_bound_to_key_and_relay() {
        let intro = IntroKeys::generate();
        let sig = intro.establish_signature(&node());
        verify_establish_intro(&intro.auth_public(), &node(), &sig).unwrap();
        // Replayed at another intro point:
        assert!(
            verify_establish_intro(&intro.auth_public(), &NodeId::from_bytes([8; 32]), &sig)
                .is_err()
        );
        // Claimed for another auth key:
        let other = IntroKeys::generate();
        assert!(verify_establish_intro(&other.auth_public(), &node(), &sig).is_err());
        assert!(verify_establish_intro(&intro.auth_public(), &node(), &sig[..63]).is_err());
    }

    fn introduce(service: &ServiceKeys, intro: &IntroKeys) -> (ClientIntro, Vec<u8>) {
        ClientIntro::new(
            *service.address(),
            &intro.auth_public(),
            &intro.enc_public(),
            node(),
            random_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn full_handshake_gives_matching_session_keys() {
        let service = ServiceKeys::generate();
        let intro = IntroKeys::generate();
        let (client, payload) = introduce(&service, &intro);
        let cookie = client.cookie();

        let opened = open_introduction(service.address(), &intro, &payload).unwrap();
        assert_eq!(opened.rendezvous, node());
        assert_eq!(opened.cookie, cookie);

        let (reply, service_keys) = accept_introduction(&service, &opened).unwrap();
        let client_keys = client.finish(&reply).unwrap();
        assert_eq!(
            client_keys.client_to_service,
            service_keys.client_to_service
        );
        assert_eq!(
            client_keys.service_to_client,
            service_keys.service_to_client
        );
        assert_ne!(client_keys.client_to_service, client_keys.service_to_client);
    }

    #[test]
    fn intro_payload_hides_the_cookie_and_rendezvous() {
        let service = ServiceKeys::generate();
        let intro = IntroKeys::generate();
        let (client, payload) = introduce(&service, &intro);
        let cookie = client.cookie();
        assert!(!payload.windows(32).any(|w| w == cookie));
        assert!(!payload.windows(32).any(|w| w == node().as_bytes()));
    }

    #[test]
    fn only_the_right_intro_key_opens_an_introduction() {
        let service = ServiceKeys::generate();
        let intro = IntroKeys::generate();
        let (_, payload) = introduce(&service, &intro);
        let wrong_intro = IntroKeys::generate();
        assert!(open_introduction(service.address(), &wrong_intro, &payload).is_err());
        let wrong_service = ServiceKeys::generate();
        assert!(open_introduction(wrong_service.address(), &intro, &payload).is_err());
    }

    #[test]
    fn tampered_introduction_is_rejected() {
        let service = ServiceKeys::generate();
        let intro = IntroKeys::generate();
        let (_, mut payload) = introduce(&service, &intro);
        let last = payload.len() - 1;
        payload[last] ^= 1;
        assert!(open_introduction(service.address(), &intro, &payload).is_err());
        assert!(open_introduction(service.address(), &intro, b"garbage").is_err());
    }

    #[test]
    fn impostor_service_cannot_complete_the_rendezvous() {
        let real = ServiceKeys::generate();
        let impostor = ServiceKeys::generate();
        let intro = IntroKeys::generate();
        let (client, payload) = introduce(&real, &intro);
        // Even with the decrypted introduction, the impostor's signature is
        // not by the real address's key.
        let opened = open_introduction(real.address(), &intro, &payload).unwrap();
        let (reply, _) = accept_introduction(&impostor, &opened).unwrap();
        assert_eq!(client.finish(&reply).err(), Some(CryptoError::BadSignature));
    }

    #[test]
    fn reply_for_another_cookie_is_rejected() {
        let service = ServiceKeys::generate();
        let intro = IntroKeys::generate();
        let (client, payload) = introduce(&service, &intro);
        let mut opened = open_introduction(service.address(), &intro, &payload).unwrap();
        opened.cookie[0] ^= 1;
        let (reply, _) = accept_introduction(&service, &opened).unwrap();
        assert_eq!(client.finish(&reply).err(), Some(CryptoError::BadSignature));
    }
}
