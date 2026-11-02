//! MORP cryptography. Only established primitives are used:
//!
//! - Ed25519 (`ed25519-dalek`): relay identity keys and descriptor signatures.
//! - X25519 (`x25519-dalek`): key agreement in the ntor-style handshake.
//! - HKDF-SHA256 / HMAC-SHA256 (`hkdf`, `hmac`, `sha2`): key derivation and
//!   handshake authentication.
//! - ChaCha20-Poly1305 (`chacha20poly1305`): authenticated encryption of
//!   each onion layer.
//!
//! See `docs/MORP.md` for the protocol and its limitations.

pub mod keys;
pub mod ntor;
pub mod onion;

use std::fmt;

/// Fill an array from the operating system's CSPRNG.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).expect("operating system RNG unavailable");
    bytes
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// AEAD tag or handshake MAC did not verify (tampering, replay,
    /// reordering, or the wrong key).
    AuthenticationFailed,
    /// A Diffie-Hellman result was all zeros (low-order public key).
    WeakKey,
    /// The handshake was addressed to a different relay identity or onion key.
    WrongRelay,
    /// A per-hop nonce counter would wrap; the circuit must be rebuilt.
    NonceExhausted,
    BadSignature,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AuthenticationFailed => "authentication failed",
            Self::WeakKey => "peer sent a weak (low-order) public key",
            Self::WrongRelay => "handshake addressed to a different relay key",
            Self::NonceExhausted => "nonce counter exhausted",
            Self::BadSignature => "invalid signature",
        })
    }
}

impl std::error::Error for CryptoError {}
