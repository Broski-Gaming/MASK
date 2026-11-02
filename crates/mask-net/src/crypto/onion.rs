//! Per-hop authenticated encryption of onion layers.
//!
//! Each hop shares two 256-bit keys with the client (from the handshake):
//! one for cells travelling away from the client (forward) and one for cells
//! travelling back (backward). Each key is used by exactly one sender and one
//! receiver, with ChaCha20-Poly1305.
//!
//! **Nonces** are never transmitted. Each side keeps a 64-bit counter per
//! direction; the 96-bit nonce is `0x000000 | direction | counter (BE)`.
//! The sender increments after every seal. The receiver only accepts the
//! cell sealed with exactly the next counter value and increments only on
//! success. Because TCP delivers in order, this gives:
//! - no nonce reuse under a key (counters never repeat; exhaustion is an error);
//! - replay protection (a repeated cell uses an old nonce and fails to verify);
//! - reordering and deletion detection (later cells fail to verify).
//!
//! Any verification failure is fatal for the circuit, because the counters
//! can no longer be trusted to be in step.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use super::CryptoError;

const AD_LABEL: &[u8] = b"MORP-v1 cell";

/// Bytes added to every layer by the AEAD tag.
pub const TAG_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Client → relay.
    Forward,
    /// Relay → client.
    Backward,
}

impl Direction {
    const fn byte(self) -> u8 {
        match self {
            Direction::Forward => 0x01,
            Direction::Backward => 0x02,
        }
    }
}

/// One direction of one hop: either the sealing or the opening side.
pub struct CellCipher {
    aead: ChaCha20Poly1305,
    direction: Direction,
    counter: u64,
}

impl CellCipher {
    pub fn new(key: &[u8; 32], direction: Direction) -> Self {
        Self {
            aead: ChaCha20Poly1305::new(&Key::from(*key)),
            direction,
            counter: 0,
        }
    }

    /// Number of cells sealed or opened so far.
    pub fn counter(&self) -> u64 {
        self.counter
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = self.nonce()?;
        let ciphertext = self
            .aead
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &self.aad(),
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        self.counter += 1;
        Ok(ciphertext)
    }

    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = self.nonce()?;
        let plaintext = self
            .aead
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: &self.aad(),
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        self.counter += 1;
        Ok(plaintext)
    }

    fn nonce(&self) -> Result<Nonce, CryptoError> {
        if self.counter == u64::MAX {
            return Err(CryptoError::NonceExhausted);
        }
        let mut nonce = [0u8; 12];
        nonce[3] = self.direction.byte();
        nonce[4..].copy_from_slice(&self.counter.to_be_bytes());
        Ok(Nonce::from(nonce))
    }

    fn aad(&self) -> [u8; AD_LABEL.len() + 1] {
        let mut aad = [0u8; AD_LABEL.len() + 1];
        aad[..AD_LABEL.len()].copy_from_slice(AD_LABEL);
        aad[AD_LABEL.len()] = self.direction.byte();
        aad
    }

    #[cfg(test)]
    fn set_counter(&mut self, counter: u64) {
        self.counter = counter;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(key: [u8; 32]) -> (CellCipher, CellCipher) {
        (
            CellCipher::new(&key, Direction::Forward),
            CellCipher::new(&key, Direction::Forward),
        )
    }

    #[test]
    fn seal_then_open_round_trips() {
        let (mut tx, mut rx) = pair([1; 32]);
        for msg in [&b"first"[..], b"", &[0u8; 1000]] {
            let ct = tx.seal(msg).unwrap();
            assert_eq!(ct.len(), msg.len() + TAG_LEN);
            assert_eq!(rx.open(&ct).unwrap(), msg);
        }
    }

    #[test]
    fn ciphertext_hides_plaintext_and_changes_each_time() {
        let (mut tx, _) = pair([2; 32]);
        let a = tx.seal(b"same message").unwrap();
        let b = tx.seal(b"same message").unwrap();
        assert_ne!(a, b);
        assert!(!a.windows(4).any(|w| w == b"same"));
    }

    #[test]
    fn tampering_is_detected() {
        let (mut tx, mut rx) = pair([3; 32]);
        let mut ct = tx.seal(b"hello").unwrap();
        ct[0] ^= 0x80;
        assert_eq!(rx.open(&ct), Err(CryptoError::AuthenticationFailed));
    }

    #[test]
    fn truncated_ciphertext_is_rejected() {
        let (mut tx, mut rx) = pair([3; 32]);
        let ct = tx.seal(b"hello").unwrap();
        assert!(rx.open(&ct[..ct.len() - 1]).is_err());
        assert!(rx.open(&[]).is_err());
    }

    #[test]
    fn replay_is_rejected() {
        let (mut tx, mut rx) = pair([4; 32]);
        let ct = tx.seal(b"pay once").unwrap();
        rx.open(&ct).unwrap();
        assert_eq!(rx.open(&ct), Err(CryptoError::AuthenticationFailed));
    }

    #[test]
    fn reordering_and_dropping_are_detected() {
        let (mut tx, mut rx) = pair([5; 32]);
        let _first = tx.seal(b"1").unwrap();
        let second = tx.seal(b"2").unwrap();
        assert!(rx.open(&second).is_err());
    }

    #[test]
    fn failed_open_does_not_advance_counter() {
        let (mut tx, mut rx) = pair([6; 32]);
        let ct = tx.seal(b"ok").unwrap();
        assert!(rx.open(b"garbage garbage garbage").is_err());
        assert_eq!(rx.counter(), 0);
        assert_eq!(rx.open(&ct).unwrap(), b"ok");
    }

    #[test]
    fn wrong_key_or_direction_fails() {
        let mut tx = CellCipher::new(&[7; 32], Direction::Forward);
        let ct = tx.seal(b"x").unwrap();
        assert!(
            CellCipher::new(&[8; 32], Direction::Forward)
                .open(&ct)
                .is_err()
        );
        assert!(
            CellCipher::new(&[7; 32], Direction::Backward)
                .open(&ct)
                .is_err()
        );
    }

    #[test]
    fn counter_exhaustion_is_an_error_not_a_wrap() {
        let (mut tx, _) = pair([9; 32]);
        tx.set_counter(u64::MAX - 1);
        tx.seal(b"last").unwrap();
        assert_eq!(tx.seal(b"one too many"), Err(CryptoError::NonceExhausted));
    }
}
