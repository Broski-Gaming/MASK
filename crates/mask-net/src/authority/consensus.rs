//! Signed consensus documents.
//!
//! ```text
//! body      = postcard(version, network, sequence, valid_after, fresh_until,
//!                      valid_until, [relay descriptor (binary, self-signed)])
//! signature = Ed25519(authority identity, "MORP-v3 consensus\0" || body)
//! ```
//!
//! A client accepts a consensus only if **all** of these hold:
//! - at least one signature verifies under an authority key pinned in its
//!   `network.toml` (signatures by unknown keys are ignored);
//! - the network name matches;
//! - `valid_after - skew <= now <= valid_until + skew`;
//! - every relay descriptor verifies under its own identity key;
//! - its sequence is newer than the consensus it already has
//!   (checked by [`TrustedRelays::install_consensus`]).
//!
//! [`TrustedRelays::install_consensus`]: crate::trust::TrustedRelays::install_consensus

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::AuthorityKeys;
use crate::NetError;
use crate::config::NetworkConfig;
use crate::descriptor::RelayDescriptor;
use crate::protocol::{MORP_VERSION, decode, encode};

const DOMAIN: &[u8] = b"MORP-v3 consensus\0";
/// Most relays in one consensus (keeps the document inside one frame).
pub const MAX_CONSENSUS_RELAYS: usize = 200;
/// Tolerated clock difference between machines, in seconds.
pub const CLOCK_SKEW: u64 = 300;

#[derive(Serialize, Deserialize)]
struct Body {
    version: u16,
    network: String,
    sequence: u64,
    valid_after: u64,
    fresh_until: u64,
    valid_until: u64,
    relays: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusSignature {
    /// Ed25519 identity of the signing authority.
    pub authority: [u8; 32],
    pub signature: Vec<u8>,
}

/// A consensus as transmitted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedConsensus {
    pub body: Vec<u8>,
    pub signatures: Vec<ConsensusSignature>,
}

/// A verified consensus.
#[derive(Clone, Debug)]
pub struct Consensus {
    pub network: String,
    pub sequence: u64,
    pub valid_after: u64,
    pub fresh_until: u64,
    pub valid_until: u64,
    pub relays: Vec<RelayDescriptor>,
    /// Names of the pinned authorities whose signatures verified.
    pub signed_by: Vec<String>,
}

/// Timing of a consensus to be signed.
#[derive(Clone, Copy, Debug)]
pub struct Validity {
    pub sequence: u64,
    pub valid_after: u64,
    pub fresh_until: u64,
    pub valid_until: u64,
}

impl SignedConsensus {
    pub fn sign(
        keys: &AuthorityKeys,
        network: &str,
        validity: Validity,
        relays: &[RelayDescriptor],
    ) -> Result<Self, NetError> {
        if relays.len() > MAX_CONSENSUS_RELAYS {
            return Err(NetError::InvalidConfig(format!(
                "more than {MAX_CONSENSUS_RELAYS} relays"
            )));
        }
        let body = encode(&Body {
            version: MORP_VERSION,
            network: network.to_owned(),
            sequence: validity.sequence,
            valid_after: validity.valid_after,
            fresh_until: validity.fresh_until,
            valid_until: validity.valid_until,
            relays: relays.iter().map(RelayDescriptor::to_wire).collect(),
        });
        let mut message = DOMAIN.to_vec();
        message.extend_from_slice(&body);
        let signature = keys.sign(&message).to_vec();
        Ok(Self {
            body,
            signatures: vec![ConsensusSignature {
                authority: keys.identity_public(),
                signature,
            }],
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        encode(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NetError> {
        decode(bytes).map_err(|e| NetError::Untrusted(format!("malformed consensus: {e}")))
    }

    /// Verify against the pinned authorities in `network` at time `now`.
    pub fn verify(&self, network: &NetworkConfig, now: u64) -> Result<Consensus, NetError> {
        let untrusted = |why: String| NetError::Untrusted(format!("consensus rejected: {why}"));
        let mut message = DOMAIN.to_vec();
        message.extend_from_slice(&self.body);
        let mut signed_by = Vec::new();
        for sig in &self.signatures {
            let Some(authority) = network.authority_by_identity(&sig.authority) else {
                continue; // not one of ours
            };
            let Ok(key) = VerifyingKey::from_bytes(&sig.authority) else {
                continue;
            };
            let Ok(bytes) = <[u8; 64]>::try_from(sig.signature.as_slice()) else {
                continue;
            };
            if key
                .verify_strict(&message, &Signature::from_bytes(&bytes))
                .is_ok()
                && !signed_by.contains(&authority.name)
            {
                signed_by.push(authority.name.clone());
            }
        }
        if signed_by.is_empty() {
            return Err(untrusted(
                "no valid signature from a pinned authority".into(),
            ));
        }

        let body: Body =
            decode(&self.body).map_err(|e| untrusted(format!("malformed body: {e}")))?;
        if body.version != MORP_VERSION {
            return Err(untrusted(format!(
                "MORP version {} not supported",
                body.version
            )));
        }
        if body.network != network.name {
            return Err(untrusted(format!(
                "for network \"{}\", not \"{}\"",
                body.network, network.name
            )));
        }
        if !(body.valid_after <= body.fresh_until && body.fresh_until <= body.valid_until) {
            return Err(untrusted("inconsistent validity times".into()));
        }
        if now + CLOCK_SKEW < body.valid_after {
            return Err(untrusted("not valid yet (check the clocks)".into()));
        }
        if now > body.valid_until + CLOCK_SKEW {
            return Err(untrusted("expired".into()));
        }
        if body.relays.len() > MAX_CONSENSUS_RELAYS {
            return Err(untrusted("too many relays".into()));
        }
        let relays = body
            .relays
            .iter()
            .map(|wire| RelayDescriptor::from_wire(wire))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| untrusted(e.to_string()))?;
        Ok(Consensus {
            network: body.network,
            sequence: body.sequence,
            valid_after: body.valid_after,
            fresh_until: body.fresh_until,
            valid_until: body.valid_until,
            relays,
            signed_by,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthorityInfo;
    use crate::crypto::keys::RelayKeys;
    use crate::identity::Role;
    use crate::scope::NetworkScope;

    fn network(keys: &AuthorityKeys) -> NetworkConfig {
        NetworkConfig {
            name: "testnet".into(),
            scope: NetworkScope::Private,
            authorities: vec![AuthorityInfo {
                name: "auth1".into(),
                address: "10.0.0.1:7300".parse().unwrap(),
                identity: keys.identity_public(),
                link_key: keys.link_public(),
            }],
        }
    }

    fn validity(now: u64) -> Validity {
        Validity {
            sequence: 42,
            valid_after: now,
            fresh_until: now + 60,
            valid_until: now + 600,
        }
    }

    fn relay() -> RelayDescriptor {
        RelayDescriptor::sign(
            &RelayKeys::generate(),
            "entry1",
            Role::Entry,
            "10.0.0.2:7101".parse().unwrap(),
        )
    }

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn signed_consensus_verifies_and_round_trips() {
        let keys = AuthorityKeys::generate();
        let relays = vec![relay()];
        let doc = SignedConsensus::sign(&keys, "testnet", validity(NOW), &relays).unwrap();
        let doc = SignedConsensus::from_bytes(&doc.to_bytes()).unwrap();
        let consensus = doc.verify(&network(&keys), NOW + 10).unwrap();
        assert_eq!(consensus.sequence, 42);
        assert_eq!(consensus.relays, relays);
        assert_eq!(consensus.signed_by, vec!["auth1".to_owned()]);
    }

    #[test]
    fn forged_consensus_from_an_unpinned_key_is_rejected() {
        let real = AuthorityKeys::generate();
        let forger = AuthorityKeys::generate();
        let doc = SignedConsensus::sign(&forger, "testnet", validity(NOW), &[relay()]).unwrap();
        assert!(matches!(
            doc.verify(&network(&real), NOW),
            Err(NetError::Untrusted(_))
        ));
    }

    #[test]
    fn tampered_body_is_rejected() {
        let keys = AuthorityKeys::generate();
        let mut doc = SignedConsensus::sign(&keys, "testnet", validity(NOW), &[relay()]).unwrap();
        let last = doc.body.len() - 1;
        doc.body[last] ^= 1;
        assert!(doc.verify(&network(&keys), NOW).is_err());
    }

    #[test]
    fn signature_copied_from_an_unpinned_key_does_not_count() {
        // Relabel a forged signature with the pinned authority's key.
        let real = AuthorityKeys::generate();
        let forger = AuthorityKeys::generate();
        let mut doc = SignedConsensus::sign(&forger, "testnet", validity(NOW), &[]).unwrap();
        doc.signatures[0].authority = real.identity_public();
        assert!(doc.verify(&network(&real), NOW).is_err());
    }

    #[test]
    fn expired_future_and_wrong_network_consensuses_are_rejected() {
        let keys = AuthorityKeys::generate();
        let net = network(&keys);
        let doc = SignedConsensus::sign(&keys, "testnet", validity(NOW), &[]).unwrap();
        assert!(
            doc.verify(&net, NOW + 600 + CLOCK_SKEW + 1).is_err(),
            "expired"
        );
        assert!(
            doc.verify(&net, NOW - CLOCK_SKEW - 1).is_err(),
            "not valid yet"
        );
        assert!(doc.verify(&net, NOW + 600).is_ok());
        let other = SignedConsensus::sign(&keys, "othernet", validity(NOW), &[]).unwrap();
        assert!(other.verify(&net, NOW).is_err(), "wrong network");
    }

    #[test]
    fn consensus_with_a_bad_relay_descriptor_is_rejected() {
        let keys = AuthorityKeys::generate();
        let mut d = relay();
        d.family = "changed-after-signing".into();
        let doc = SignedConsensus::sign(&keys, "testnet", validity(NOW), &[d]).unwrap();
        assert!(doc.verify(&network(&keys), NOW).is_err());
    }
}
