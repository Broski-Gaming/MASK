//! Signed, expiring service descriptors (version 2).
//!
//! A descriptor tells clients how to *introduce* themselves to the service
//! at a `.morp` address. It lists the service's introduction points: which
//! rendezvous-role relays to contact, and the per-intro public keys to use.
//! **It contains no address, port, or other location of the service.**
//!
//! It is signed with the address's own key, so:
//! - nobody else can publish or change the descriptor for an address;
//! - an address can never be pointed at a different key (the key *is* the
//!   address).
//!
//! Descriptors carry a revision (strictly increasing; the directory rejects
//! replays of older ones) and expire after at most [`MAX_LIFETIME`] seconds.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::keys::ServiceKeys;
use crate::address::MorpAddress;
use crate::identity::{NodeId, from_hex, to_hex};

pub const DESCRIPTOR_VERSION: u16 = 2;
/// Longest allowed validity period.
pub const MAX_LIFETIME: u64 = 3 * 60 * 60;
pub const DEFAULT_LIFETIME: u64 = 60 * 60;
/// Tolerated clock difference between publisher and verifier.
pub const CLOCK_SKEW: u64 = 5 * 60;
/// Most introduction points per descriptor.
pub const MAX_INTRO_POINTS: usize = 3;

const DESCRIPTOR_DOMAIN: &[u8] = b"MORP-v2 service descriptor\0";
const WITHDRAWAL_DOMAIN: &[u8] = b"MORP-v1 service withdrawal\0";

/// One introduction point: a rendezvous-role relay, and the keys the
/// service uses there. Clients find the relay's address and onion key in the
/// relay directory by its identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntroPoint {
    pub relay: NodeId,
    /// Per-intro Ed25519 key registered at the relay (not the identity key).
    pub auth_key: [u8; 32],
    /// Per-intro X25519 key that introductions are encrypted to.
    pub enc_key: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DescriptorError {
    Malformed(String),
    BadSignature,
    Expired,
    NotYetValid,
    LifetimeTooLong,
    BadIntroPoints(String),
}

impl std::fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "malformed descriptor: {why}"),
            Self::BadSignature => write!(f, "signature does not match the .morp address"),
            Self::Expired => write!(f, "descriptor has expired"),
            Self::NotYetValid => write!(f, "descriptor is dated in the future"),
            Self::LifetimeTooLong => write!(
                f,
                "descriptor validity exceeds the {MAX_LIFETIME}-second maximum"
            ),
            Self::BadIntroPoints(why) => write!(f, "invalid introduction points: {why}"),
        }
    }
}

impl std::error::Error for DescriptorError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceDescriptor {
    pub address: MorpAddress,
    pub revision: u64,
    pub published: u64,
    pub expires: u64,
    pub intro_points: Vec<IntroPoint>,
    signature: [u8; 64],
}

#[derive(Serialize)]
struct Signed<'a> {
    version: u16,
    public_key: &'a [u8; 32],
    revision: u64,
    published: u64,
    expires: u64,
    intro_points: &'a [IntroPoint],
}

#[derive(Serialize, Deserialize)]
struct IntroPointJson {
    relay: String,
    auth_key: String,
    enc_key: String,
}

#[derive(Serialize, Deserialize)]
struct DescriptorJson {
    descriptor_version: u16,
    address: String,
    revision: u64,
    published: u64,
    expires: u64,
    intro_points: Vec<IntroPointJson>,
    signature: String,
}

impl ServiceDescriptor {
    pub fn sign(
        keys: &ServiceKeys,
        intro_points: Vec<IntroPoint>,
        published: u64,
        lifetime: u64,
        revision: u64,
    ) -> Self {
        let mut descriptor = Self {
            address: *keys.address(),
            revision,
            published,
            expires: published.saturating_add(lifetime),
            intro_points,
            signature: [0; 64],
        };
        descriptor.signature = keys.sign(&descriptor.signed_bytes());
        descriptor
    }

    fn signed_bytes(&self) -> Vec<u8> {
        let fields = Signed {
            version: DESCRIPTOR_VERSION,
            public_key: self.address.public_key(),
            revision: self.revision,
            published: self.published,
            expires: self.expires,
            intro_points: &self.intro_points,
        };
        let mut bytes = DESCRIPTOR_DOMAIN.to_vec();
        bytes.extend(crate::protocol::encode(&fields));
        bytes
    }

    /// Full check: signature by the address's key, time window, intro points.
    pub fn verify(&self, now: u64) -> Result<(), DescriptorError> {
        self.address
            .verifying_key()
            .verify_strict(
                &self.signed_bytes(),
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| DescriptorError::BadSignature)?;
        if self.expires <= self.published || self.expires - self.published > MAX_LIFETIME {
            return Err(DescriptorError::LifetimeTooLong);
        }
        if self.published > now.saturating_add(CLOCK_SKEW) {
            return Err(DescriptorError::NotYetValid);
        }
        if now >= self.expires {
            return Err(DescriptorError::Expired);
        }
        let bad = |why: &str| Err(DescriptorError::BadIntroPoints(why.into()));
        if self.intro_points.is_empty() {
            return bad("none listed");
        }
        if self.intro_points.len() > MAX_INTRO_POINTS {
            return bad("too many");
        }
        for (i, ip) in self.intro_points.iter().enumerate() {
            if self.intro_points[..i].iter().any(|o| o.relay == ip.relay) {
                return bad("relay listed twice");
            }
            match VerifyingKey::from_bytes(&ip.auth_key) {
                Ok(key) if !key.is_weak() => {}
                _ => return bad("invalid auth key"),
            }
            if ip.enc_key == [0; 32] {
                return bad("invalid encryption key");
            }
        }
        Ok(())
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&DescriptorJson {
            descriptor_version: DESCRIPTOR_VERSION,
            address: self.address.host(),
            revision: self.revision,
            published: self.published,
            expires: self.expires,
            intro_points: self
                .intro_points
                .iter()
                .map(|ip| IntroPointJson {
                    relay: to_hex(ip.relay.as_bytes()),
                    auth_key: to_hex(&ip.auth_key),
                    enc_key: to_hex(&ip.enc_key),
                })
                .collect(),
            signature: to_hex(&self.signature),
        })
        .expect("descriptor serializes")
    }

    /// Parse (but do not verify) a descriptor. Call [`verify`](Self::verify).
    pub fn from_json(json: &str) -> Result<Self, DescriptorError> {
        let parsed: DescriptorJson =
            serde_json::from_str(json).map_err(|e| DescriptorError::Malformed(e.to_string()))?;
        if parsed.descriptor_version != DESCRIPTOR_VERSION {
            return Err(DescriptorError::Malformed(format!(
                "descriptor version {} not supported",
                parsed.descriptor_version
            )));
        }
        let address = MorpAddress::parse_host(&parsed.address)
            .map_err(|e| DescriptorError::Malformed(format!("address: {e}")))?;
        let hex32 = |s: &str, what: &str| {
            from_hex::<32>(s)
                .ok_or_else(|| DescriptorError::Malformed(format!("{what} is not 32 hex bytes")))
        };
        let mut intro_points = Vec::new();
        for ip in &parsed.intro_points {
            intro_points.push(IntroPoint {
                relay: NodeId::from_bytes(hex32(&ip.relay, "intro relay")?),
                auth_key: hex32(&ip.auth_key, "auth key")?,
                enc_key: hex32(&ip.enc_key, "encryption key")?,
            });
        }
        let signature = from_hex(&parsed.signature)
            .ok_or_else(|| DescriptorError::Malformed("signature is not 64 hex bytes".into()))?;
        Ok(Self {
            address,
            revision: parsed.revision,
            published: parsed.published,
            expires: parsed.expires,
            intro_points,
            signature,
        })
    }

    #[cfg(test)]
    pub(crate) fn signature_mut(&mut self) -> &mut [u8; 64] {
        &mut self.signature
    }
}

/// Signed request to remove a service's descriptor from the directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Withdrawal {
    pub address: String,
    pub revision: u64,
    pub signature: String,
}

impl Withdrawal {
    pub fn sign(keys: &ServiceKeys, revision: u64) -> Self {
        let signature = keys.sign(&Self::signed_bytes(keys.address(), revision));
        Self {
            address: keys.address().host(),
            revision,
            signature: to_hex(&signature),
        }
    }

    fn signed_bytes(address: &MorpAddress, revision: u64) -> Vec<u8> {
        let mut bytes = WITHDRAWAL_DOMAIN.to_vec();
        bytes.extend_from_slice(address.public_key());
        bytes.extend_from_slice(&revision.to_be_bytes());
        bytes
    }

    /// Verify and return the address being withdrawn.
    pub fn verify(&self) -> Result<MorpAddress, DescriptorError> {
        let address = MorpAddress::parse_host(&self.address)
            .map_err(|e| DescriptorError::Malformed(e.to_string()))?;
        let signature: [u8; 64] = from_hex(&self.signature)
            .ok_or_else(|| DescriptorError::Malformed("bad signature encoding".into()))?;
        address
            .verifying_key()
            .verify_strict(
                &Self::signed_bytes(&address, self.revision),
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| DescriptorError::BadSignature)?;
        Ok(address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hs::crypto::IntroKeys;

    const NOW: u64 = 1_800_000_000;

    pub(crate) fn intro_point(relay: u8) -> IntroPoint {
        let keys = IntroKeys::generate();
        IntroPoint {
            relay: NodeId::from_bytes([relay; 32]),
            auth_key: keys.auth_public(),
            enc_key: keys.enc_public(),
        }
    }

    fn signed(keys: &ServiceKeys) -> ServiceDescriptor {
        ServiceDescriptor::sign(keys, vec![intro_point(1)], NOW, DEFAULT_LIFETIME, 1)
    }

    #[test]
    fn valid_descriptor_verifies_and_round_trips() {
        let keys = ServiceKeys::generate();
        let d = signed(&keys);
        d.verify(NOW + 10).unwrap();
        let parsed = ServiceDescriptor::from_json(&d.to_json()).unwrap();
        assert_eq!(parsed, d);
        parsed.verify(NOW + 10).unwrap();
    }

    #[test]
    fn json_holds_no_private_key_and_no_location() {
        let keys = ServiceKeys::generate();
        let json = signed(&keys).to_json();
        assert!(json.contains(&keys.address().host()));
        for forbidden in ["secret", "private", "127.0.0.1", "endpoint", "port"] {
            assert!(!json.contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn descriptor_signed_by_another_key_is_a_forgery() {
        let victim = ServiceKeys::generate();
        let attacker = ServiceKeys::generate();
        let mut forged = signed(&attacker);
        forged.address = *victim.address();
        assert_eq!(forged.verify(NOW), Err(DescriptorError::BadSignature));
    }

    #[test]
    fn any_change_breaks_the_signature() {
        let keys = ServiceKeys::generate();
        let d = signed(&keys);

        let mut redirected = d.clone();
        redirected.intro_points[0] = intro_point(2);
        assert_eq!(redirected.verify(NOW), Err(DescriptorError::BadSignature));

        let mut extended = d.clone();
        extended.expires += 60;
        assert_eq!(extended.verify(NOW), Err(DescriptorError::BadSignature));

        let mut bumped = d.clone();
        bumped.revision += 1;
        assert_eq!(bumped.verify(NOW), Err(DescriptorError::BadSignature));

        let mut bad_sig = d;
        bad_sig.signature_mut()[0] ^= 1;
        assert_eq!(bad_sig.verify(NOW), Err(DescriptorError::BadSignature));
    }

    #[test]
    fn time_window_is_enforced() {
        let keys = ServiceKeys::generate();
        let d = signed(&keys);
        assert_eq!(
            d.verify(NOW + DEFAULT_LIFETIME),
            Err(DescriptorError::Expired)
        );
        assert_eq!(
            d.verify(NOW - CLOCK_SKEW - 1),
            Err(DescriptorError::NotYetValid)
        );
        let too_long =
            ServiceDescriptor::sign(&keys, vec![intro_point(1)], NOW, MAX_LIFETIME + 1, 1);
        assert_eq!(too_long.verify(NOW), Err(DescriptorError::LifetimeTooLong));
    }

    #[test]
    fn intro_point_list_is_validated() {
        let keys = ServiceKeys::generate();
        let sign = |ips| ServiceDescriptor::sign(&keys, ips, NOW, DEFAULT_LIFETIME, 1);
        assert!(matches!(
            sign(vec![]).verify(NOW),
            Err(DescriptorError::BadIntroPoints(_))
        ));
        assert!(matches!(
            sign((1..=4).map(intro_point).collect()).verify(NOW),
            Err(DescriptorError::BadIntroPoints(_))
        ));
        assert!(matches!(
            sign(vec![intro_point(1), intro_point(1)]).verify(NOW),
            Err(DescriptorError::BadIntroPoints(_))
        ));
        let mut weak = intro_point(1);
        weak.auth_key = [0; 32];
        weak.auth_key[0] = 1; // identity point
        assert!(matches!(
            sign(vec![weak]).verify(NOW),
            Err(DescriptorError::BadIntroPoints(_))
        ));
    }

    #[test]
    fn malformed_json_is_rejected() {
        let keys = ServiceKeys::generate();
        let good = signed(&keys).to_json();
        let bad_address = good.replace(&keys.address().id()[..10], "aaaaaaaaaa");
        for json in [
            "".to_owned(),
            "{}".to_owned(),
            "not json".to_owned(),
            good.replace("\"descriptor_version\": 2", "\"descriptor_version\": 1"),
            bad_address,
        ] {
            assert!(
                matches!(
                    ServiceDescriptor::from_json(&json),
                    Err(DescriptorError::Malformed(_))
                ),
                "{json}"
            );
        }
    }

    #[test]
    fn withdrawal_is_bound_to_key_and_revision() {
        let keys = ServiceKeys::generate();
        let w = Withdrawal::sign(&keys, 42);
        assert_eq!(w.verify().unwrap(), *keys.address());

        let mut other_revision = w.clone();
        other_revision.revision = 43;
        assert_eq!(other_revision.verify(), Err(DescriptorError::BadSignature));

        let mut other_service = w;
        other_service.address = ServiceKeys::generate().address().host();
        assert_eq!(other_service.verify(), Err(DescriptorError::BadSignature));
    }
}
