//! Signed consensus documents.
//!
//! ```text
//! body      = postcard(format = 2, network, sequence, valid_after, fresh_until,
//!                      valid_until, [entry])
//! entry     = (relay descriptor (binary, self-signed), operator, listed_since)
//! signature = Ed25519(authority identity, "MORP-v3 consensus v2\0" || body)
//! ```
//!
//! `operator` and `listed_since` are assigned by the authority (v0.7): who
//! runs the relay (from `approved-relays.toml`) and when the authority first
//! listed it. The authority's signature covers them; the relay's does not.
//!
//! A client accepts a consensus only if **all** of these hold:
//! - at least one signature verifies under an authority key pinned in its
//!   `network.toml` (signatures by unknown keys are ignored);
//! - the network name matches;
//! - `valid_after - skew <= now <= valid_until + skew`;
//! - every relay descriptor verifies under its own identity key;
//! - no two entries share an identity, nickname, address, onion key, or link
//!   key (an honest authority never signs that; v0.7);
//! - it is valid for at most [`MAX_LIFETIME`] and lists nobody "in the future";
//! - its sequence is newer than the consensus it already has
//!   (checked by [`TrustedRelays::install_consensus`]).
//!
//! [`TrustedRelays::install_consensus`]: crate::trust::TrustedRelays::install_consensus

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::AuthorityKeys;
use crate::NetError;
use crate::config::NetworkConfig;
use crate::descriptor::{MAX_FAMILY_LEN, RelayDescriptor, valid_label};
use crate::protocol::{decode, encode};

const DOMAIN: &[u8] = b"MORP-v3 consensus v2\0";
/// Consensus document format (v0.7 added operators and listing times).
pub const CONSENSUS_FORMAT: u16 = 2;
/// Longest a consensus may be valid, from `valid_after` to `valid_until`.
/// A document valid for longer could be replayed for that long.
pub const MAX_LIFETIME: u64 = 86_400;
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
    relays: Vec<Entry>,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    descriptor: Vec<u8>,
    operator: String,
    listed_since: u64,
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
        if let Some(d) = relays
            .iter()
            .find(|d| !valid_label(&d.operator, MAX_FAMILY_LEN))
        {
            return Err(NetError::InvalidConfig(format!(
                "invalid operator label for {}",
                d.nickname
            )));
        }
        let body = encode(&Body {
            version: CONSENSUS_FORMAT,
            network: network.to_owned(),
            sequence: validity.sequence,
            valid_after: validity.valid_after,
            fresh_until: validity.fresh_until,
            valid_until: validity.valid_until,
            relays: relays
                .iter()
                .map(|d| Entry {
                    descriptor: d.to_wire(),
                    operator: d.operator.clone(),
                    listed_since: d.listed_since,
                })
                .collect(),
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
        if body.version != CONSENSUS_FORMAT {
            return Err(untrusted(format!(
                "consensus format {} not supported (need {CONSENSUS_FORMAT})",
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
        if body.valid_until - body.valid_after > MAX_LIFETIME {
            return Err(untrusted(format!(
                "valid for {} s; at most {MAX_LIFETIME} s is accepted",
                body.valid_until - body.valid_after
            )));
        }
        if body.relays.len() > MAX_CONSENSUS_RELAYS {
            return Err(untrusted("too many relays".into()));
        }
        let mut relays = Vec::with_capacity(body.relays.len());
        for entry in &body.relays {
            let mut d = RelayDescriptor::from_wire(&entry.descriptor)
                .map_err(|e| untrusted(e.to_string()))?;
            if !valid_label(&entry.operator, MAX_FAMILY_LEN) {
                return Err(untrusted(format!("invalid operator for {}", d.nickname)));
            }
            if entry.listed_since > body.valid_after + CLOCK_SKEW {
                return Err(untrusted(format!(
                    "{} is listed since a time after the consensus",
                    d.nickname
                )));
            }
            d.operator = entry.operator.clone();
            d.listed_since = entry.listed_since;
            relays.push(d);
        }
        check_unique(&relays).map_err(untrusted)?;
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

/// No two relays may share an identity, nickname, address, onion key, or
/// link key. Shared keys or addresses would let one relay borrow another's
/// liveness, or be mistaken for it when a link key is looked up. An honest
/// authority refuses such uploads, so a consensus containing them is not
/// trusted at all.
pub fn check_unique(relays: &[RelayDescriptor]) -> Result<(), String> {
    use std::collections::HashSet;
    let mut ids = HashSet::new();
    let mut nicks = HashSet::new();
    let mut addrs = HashSet::new();
    let mut onion = HashSet::new();
    let mut link = HashSet::new();
    for d in relays {
        let clash = if !ids.insert(d.node_id) {
            "identity"
        } else if !nicks.insert(d.nickname.as_str()) {
            "nickname"
        } else if !addrs.insert(d.addr) {
            "address"
        } else if !onion.insert(d.onion_key) {
            "onion key"
        } else if !link.insert(d.link_key) {
            "link key"
        } else {
            continue;
        };
        return Err(format!("two relays share a {clash} ({})", d.nickname));
    }
    Ok(())
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
            relay_policy: crate::config::RelayPolicy::default_for(NetworkScope::Private),
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
    fn operator_and_listing_time_travel_under_the_authority_signature() {
        let keys = AuthorityKeys::generate();
        let mut d = relay();
        d.operator = "alice".into();
        d.listed_since = NOW - 3600;
        let doc = SignedConsensus::sign(&keys, "testnet", validity(NOW), &[d.clone()]).unwrap();
        let consensus = doc.verify(&network(&keys), NOW).unwrap();
        assert_eq!(consensus.relays[0].operator, "alice");
        assert_eq!(consensus.relays[0].listed_since, NOW - 3600);
        // The relay's own signature does not cover them, the authority's does:
        // changing them breaks the consensus signature.
        let mut tampered = doc.clone();
        let pos = tampered
            .body
            .windows(5)
            .position(|w| w == b"alice")
            .unwrap();
        tampered.body[pos] = b'm';
        assert!(tampered.verify(&network(&keys), NOW).is_err());
    }

    #[test]
    fn hostile_consensus_contents_are_rejected() {
        // Regression (v0.7): a consensus could list two relays sharing a
        // link key or address, or be valid for years.
        let keys = AuthorityKeys::generate();
        let net = network(&keys);
        let honest = relay();
        let sybil_keys = RelayKeys::generate();
        let shares_link = RelayDescriptor::sign_claiming(
            &sybil_keys,
            "sybil",
            Role::Entry,
            "10.0.0.3:7101".parse().unwrap(),
            "",
            sybil_keys.onion_public(),
            honest.link_key,
        );
        let shares_addr =
            RelayDescriptor::sign(&RelayKeys::generate(), "sybil2", Role::Middle, honest.addr);
        for (twin, what) in [(shares_link, "link key"), (shares_addr, "address")] {
            let doc =
                SignedConsensus::sign(&keys, "testnet", validity(NOW), &[honest.clone(), twin])
                    .unwrap();
            let err = doc.verify(&net, NOW).unwrap_err().to_string();
            assert!(err.contains(what), "{err}");
        }

        let forever = Validity {
            sequence: 1,
            valid_after: NOW,
            fresh_until: NOW + 60,
            valid_until: NOW + 10 * 365 * 86_400,
        };
        let doc = SignedConsensus::sign(&keys, "testnet", forever, &[]).unwrap();
        assert!(doc.verify(&net, NOW).is_err(), "decade-long consensus");

        let mut future = relay();
        future.listed_since = NOW + 86_400;
        let doc = SignedConsensus::sign(&keys, "testnet", validity(NOW), &[future]).unwrap();
        assert!(doc.verify(&net, NOW).is_err(), "listed in the future");
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
