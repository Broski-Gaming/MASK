//! Cryptographic `.morp` service addresses.
//!
//! A `.morp` address *is* a service's Ed25519 public key, plus a checksum
//! and a version, in lowercase Base32. Nobody chooses an address; it is
//! computed from the key, and only the holder of the matching private key
//! can sign for it. There are no aliases or human-readable names.
//!
//! ```text
//! id       = base32_lowercase_nopad( PUBKEY (32) || CHECKSUM (2) || VERSION (1) )   → 56 chars
//! CHECKSUM = SHA3-256( "MORP address checksum v1" || PUBKEY || VERSION )[0..2]
//! VERSION  = 0x01
//! host     = id + ".morp"
//! URL      = "morp://" + host + "/"
//! ```
//!
//! The layout follows Tor's v3 onion addresses; the checksum domain
//! separator and version byte are MORP's own, so a `.morp` id is never a
//! valid `.onion` id or the other way round. See `docs/MORP_ADDRESSES.md`.

use std::fmt;

use data_encoding::BASE32_NOPAD;
use ed25519_dalek::VerifyingKey;
use sha3::{Digest, Sha3_256};

/// Version byte of the current address format.
pub const ADDRESS_VERSION: u8 = 0x01;
/// Length of the Base32 identity (without the `.morp` suffix).
pub const ID_LEN: usize = 56;
pub const SUFFIX: &str = ".morp";
pub const SCHEME: &str = "morp";

const CHECKSUM_DOMAIN: &[u8] = b"MORP address checksum v1";
const RAW_LEN: usize = 32 + 2 + 1;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MorpAddress {
    public_key: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddressError {
    /// The identity is not 56 characters long.
    WrongLength(usize),
    /// A character outside lowercase `a-z` and `2-7`.
    InvalidCharacter(char),
    UnsupportedVersion(u8),
    BadChecksum,
    /// The bytes are not a usable Ed25519 public key.
    InvalidKey,
    /// The host does not end in `.morp`.
    MissingSuffix,
    /// The text is not a well-formed `morp://` URL.
    BadUrl(String),
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength(n) => write!(
                f,
                "a .morp identity is {ID_LEN} characters long, this one has {n}"
            ),
            Self::InvalidCharacter(c) => write!(
                f,
                "invalid character {c:?}: .morp identities use only lowercase a-z and digits 2-7"
            ),
            Self::UnsupportedVersion(v) => write!(f, "unsupported address version {v}"),
            Self::BadChecksum => write!(
                f,
                "checksum does not match (the address is mistyped or corrupted)"
            ),
            Self::InvalidKey => write!(f, "the address does not contain a valid public key"),
            Self::MissingSuffix => write!(f, "MORP addresses end in .morp"),
            Self::BadUrl(why) => write!(f, "not a valid morp:// URL: {why}"),
        }
    }
}

impl std::error::Error for AddressError {}

impl MorpAddress {
    /// The address for an Ed25519 public key. Fails for keys that are not
    /// valid curve points or are of small order.
    pub fn from_public_key(public_key: [u8; 32]) -> Result<Self, AddressError> {
        let key = VerifyingKey::from_bytes(&public_key).map_err(|_| AddressError::InvalidKey)?;
        if key.is_weak() {
            return Err(AddressError::InvalidKey);
        }
        Ok(Self { public_key })
    }

    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(&self.public_key).expect("validated when the address was created")
    }

    /// The 56-character identity.
    pub fn id(&self) -> String {
        let mut raw = [0u8; RAW_LEN];
        raw[..32].copy_from_slice(&self.public_key);
        raw[32..34].copy_from_slice(&checksum(&self.public_key, ADDRESS_VERSION));
        raw[34] = ADDRESS_VERSION;
        BASE32_NOPAD.encode(&raw).to_ascii_lowercase()
    }

    /// `<id>.morp`
    pub fn host(&self) -> String {
        format!("{}{SUFFIX}", self.id())
    }

    /// `morp://<id>.morp/`
    pub fn url(&self) -> String {
        format!("{SCHEME}://{}/", self.host())
    }

    /// Parse a bare 56-character identity.
    pub fn parse_id(id: &str) -> Result<Self, AddressError> {
        let len = id.chars().count();
        if len != ID_LEN {
            return Err(AddressError::WrongLength(len));
        }
        if let Some(c) = id.chars().find(|c| !matches!(c, 'a'..='z' | '2'..='7')) {
            return Err(AddressError::InvalidCharacter(c));
        }
        let raw = BASE32_NOPAD
            .decode(id.to_ascii_uppercase().as_bytes())
            .map_err(|_| AddressError::BadUrl("invalid Base32".into()))?;
        if raw.len() != RAW_LEN {
            return Err(AddressError::WrongLength(len));
        }

        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&raw[..32]);
        let version = raw[34];
        // Check the checksum first: a typo in the last character changes the
        // version bits, and should be reported as a typo, not a new version.
        if raw[32..34] != checksum(&public_key, version) {
            return Err(AddressError::BadChecksum);
        }
        if version != ADDRESS_VERSION {
            return Err(AddressError::UnsupportedVersion(version));
        }
        Self::from_public_key(public_key)
    }

    /// Parse `<id>.morp`.
    pub fn parse_host(host: &str) -> Result<Self, AddressError> {
        let id = host
            .strip_suffix(SUFFIX)
            .ok_or(AddressError::MissingSuffix)?;
        Self::parse_id(id)
    }

    /// Parse `<id>`, `<id>.morp`, or a `morp://` URL (path ignored).
    pub fn parse(text: &str) -> Result<Self, AddressError> {
        let text = text.trim();
        if text.contains("://") {
            parse_url(text).map(|(address, _)| address)
        } else if text.ends_with(SUFFIX) {
            Self::parse_host(text)
        } else {
            Self::parse_id(text)
        }
    }
}

impl fmt::Display for MorpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.host())
    }
}

impl fmt::Debug for MorpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MorpAddress({})", self.host())
    }
}

fn checksum(public_key: &[u8; 32], version: u8) -> [u8; 2] {
    let digest = Sha3_256::new()
        .chain_update(CHECKSUM_DOMAIN)
        .chain_update(public_key)
        .chain_update([version])
        .finalize();
    [digest[0], digest[1]]
}

/// Parse `morp://<id>.morp/path?query`. Returns the address and the
/// path-and-query (always starting with `/`). Ports, user names, and
/// fragments are not part of a MORP address and are rejected or dropped.
pub fn parse_url(text: &str) -> Result<(MorpAddress, String), AddressError> {
    let bad = |why: &str| AddressError::BadUrl(why.to_owned());
    let rest = text
        .strip_prefix("morp://")
        .ok_or_else(|| bad("must start with morp://"))?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    if authority.contains('@') {
        return Err(bad("user names are not allowed"));
    }
    if authority.contains(':') {
        return Err(bad(
            "ports are not allowed; the address alone identifies the service",
        ));
    }
    let address = MorpAddress::parse_host(authority)?;

    let without_fragment = tail.split('#').next().unwrap_or("");
    let path = if without_fragment.is_empty() {
        "/".to_owned()
    } else if without_fragment.starts_with('?') {
        format!("/{without_fragment}")
    } else {
        without_fragment.to_owned()
    };
    if path.chars().any(|c| c.is_control() || c == ' ') {
        return Err(bad("the path contains spaces or control characters"));
    }
    Ok((address, path))
}

/// True for `http://` / `https://` URLs whose host is a `.morp` name. Such
/// URLs must never be sent to public DNS or the internet.
pub fn is_clearnet_morp_url(text: &str) -> bool {
    let Ok(url) = url::Url::parse(text) else {
        return false;
    };
    matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some_and(|host| {
            let host = host.trim_end_matches('.');
            host == "morp" || host.ends_with(SUFFIX)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> [u8; 32] {
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
    }

    fn address(seed: u8) -> MorpAddress {
        MorpAddress::from_public_key(key(seed)).unwrap()
    }

    /// Re-encode raw bytes as an id, bypassing all checks.
    fn raw_id(public_key: &[u8; 32], checksum: [u8; 2], version: u8) -> String {
        let mut raw = Vec::from(&public_key[..]);
        raw.extend_from_slice(&checksum);
        raw.push(version);
        BASE32_NOPAD.encode(&raw).to_ascii_lowercase()
    }

    #[test]
    fn id_is_56_lowercase_base32_characters() {
        let id = address(1).id();
        assert_eq!(id.len(), ID_LEN);
        assert!(id.chars().all(|c| matches!(c, 'a'..='z' | '2'..='7')));
        assert!(address(1).url().starts_with("morp://"));
        assert!(address(1).url().ends_with(".morp/"));
    }

    #[test]
    fn address_is_deterministic_and_round_trips() {
        assert_eq!(address(7).id(), address(7).id());
        assert_ne!(address(7).id(), address(8).id());
        let a = address(7);
        assert_eq!(MorpAddress::parse_id(&a.id()).unwrap(), a);
        assert_eq!(MorpAddress::parse_host(&a.host()).unwrap(), a);
        assert_eq!(MorpAddress::parse(&a.url()).unwrap(), a);
        assert_eq!(*a.public_key(), key(7));
    }

    #[test]
    fn layout_matches_the_specification() {
        let a = address(3);
        let raw = BASE32_NOPAD
            .decode(a.id().to_ascii_uppercase().as_bytes())
            .unwrap();
        assert_eq!(&raw[..32], a.public_key());
        let digest =
            Sha3_256::digest([&b"MORP address checksum v1"[..], a.public_key(), &[0x01]].concat());
        assert_eq!(&raw[32..34], &digest[..2]);
        assert_eq!(raw[34], 0x01);
    }

    #[test]
    fn known_answer_vector_is_stable() {
        // Regression vector: Ed25519 seed of 32 × 0x01. If this changes,
        // every existing .morp address has changed.
        assert_eq!(
            address(1).id(),
            include_str!("../tests/vectors/address_seed01.txt").trim()
        );
    }

    #[test]
    fn rejects_wrong_lengths() {
        let id = address(1).id();
        assert_eq!(
            MorpAddress::parse_id(&id[..55]),
            Err(AddressError::WrongLength(55))
        );
        assert_eq!(
            MorpAddress::parse_id(&format!("{id}a")),
            Err(AddressError::WrongLength(57))
        );
        assert_eq!(MorpAddress::parse_id(""), Err(AddressError::WrongLength(0)));
    }

    #[test]
    fn rejects_invalid_characters_and_uppercase() {
        let id = address(1).id();
        for bad in ['1', '8', '0', '9', 'A', '=', '-', 'é'] {
            let mut chars: Vec<char> = id.chars().collect();
            chars[10] = bad;
            let text: String = chars.into_iter().collect();
            assert!(
                matches!(
                    MorpAddress::parse_id(&text),
                    Err(AddressError::InvalidCharacter(_) | AddressError::WrongLength(_))
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn rejects_bad_checksum() {
        let a = address(1);
        let good = checksum(a.public_key(), ADDRESS_VERSION);
        let wrong = [good[0] ^ 1, good[1]];
        assert_eq!(
            MorpAddress::parse_id(&raw_id(a.public_key(), wrong, ADDRESS_VERSION)),
            Err(AddressError::BadChecksum)
        );

        // A single mistyped character in the key part.
        let mut chars: Vec<char> = a.id().chars().collect();
        chars[5] = if chars[5] == 'a' { 'b' } else { 'a' };
        let typo: String = chars.into_iter().collect();
        assert!(MorpAddress::parse_id(&typo).is_err());
    }

    #[test]
    fn rejects_other_versions_even_with_matching_checksum() {
        let a = address(1);
        for version in [0x00, 0x02, 0x03, 0xff] {
            let id = raw_id(a.public_key(), checksum(a.public_key(), version), version);
            assert_eq!(
                MorpAddress::parse_id(&id),
                Err(AddressError::UnsupportedVersion(version))
            );
        }
    }

    #[test]
    fn tor_style_checksum_is_not_accepted() {
        let a = address(1);
        let tor_like = Sha3_256::digest(
            [&b".onion checksum"[..], a.public_key(), &[ADDRESS_VERSION]].concat(),
        );
        let id = raw_id(a.public_key(), [tor_like[0], tor_like[1]], ADDRESS_VERSION);
        assert_eq!(MorpAddress::parse_id(&id), Err(AddressError::BadChecksum));
    }

    #[test]
    fn rejects_invalid_and_weak_keys_with_valid_checksums() {
        // y = 1 is the identity point: valid encoding, small order.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        // y = 2 does not decode to a curve point.
        let mut not_on_curve = [0u8; 32];
        not_on_curve[0] = 2;
        for public_key in [identity, not_on_curve] {
            let id = raw_id(
                &public_key,
                checksum(&public_key, ADDRESS_VERSION),
                ADDRESS_VERSION,
            );
            assert_eq!(MorpAddress::parse_id(&id), Err(AddressError::InvalidKey));
            assert_eq!(
                MorpAddress::from_public_key(public_key),
                Err(AddressError::InvalidKey)
            );
        }
    }

    #[test]
    fn parses_urls_and_rejects_malformed_ones() {
        let a = address(2);
        let host = a.host();
        assert_eq!(
            parse_url(&format!("morp://{host}")).unwrap(),
            (a, "/".into())
        );
        assert_eq!(
            parse_url(&format!("morp://{host}/css/site.css?v=2#top")).unwrap(),
            (a, "/css/site.css?v=2".into())
        );
        assert_eq!(
            parse_url(&format!("morp://{host}?q=1")).unwrap(),
            (a, "/?q=1".into())
        );
        for bad in [
            format!("https://{host}/"),
            format!("morp://{host}:8080/"),
            format!("morp://user@{host}/"),
            format!("morp://{}/", a.id()),
            format!("morp://{host}/a b"),
            "morp://example.morp/".to_owned(),
        ] {
            assert!(parse_url(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn detects_morp_names_in_clearnet_urls() {
        let host = address(2).host();
        assert!(is_clearnet_morp_url(&format!("https://{host}/")));
        assert!(is_clearnet_morp_url("http://anything.morp/page"));
        assert!(is_clearnet_morp_url("https://x.morp./"));
        assert!(!is_clearnet_morp_url("https://example.com/morp"));
        assert!(!is_clearnet_morp_url(&format!("morp://{host}/")));
    }
}

#[cfg(test)]
mod typo_tests {
    use super::*;

    #[test]
    fn typo_in_the_last_character_is_reported_as_a_checksum_error() {
        let id = MorpAddress::from_public_key(
            ed25519_dalek::SigningKey::from_bytes(&[4; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap()
        .id();
        for replacement in ['a', 'b', 'q', '7'] {
            let mut chars: Vec<char> = id.chars().collect();
            if chars[55] == replacement {
                continue;
            }
            chars[55] = replacement;
            let typo: String = chars.into_iter().collect();
            assert_eq!(
                MorpAddress::parse_id(&typo),
                Err(AddressError::BadChecksum),
                "{typo}"
            );
        }
    }
}
