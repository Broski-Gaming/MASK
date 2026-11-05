//! Relay key material.
//!
//! - **Identity key** (Ed25519): long-term, stored in `<data_dir>/identity.key`
//!   with mode 0600. Its public half is the relay's [`NodeId`].
//! - **Onion key** (X25519): generated fresh every time the relay starts and
//!   never written to disk. It is bound to the identity by the signed relay
//!   descriptor. Restarting a relay therefore invalidates old descriptors.
//! - **Link key** (X25519): also fresh per run and never written to disk.
//!   It authenticates the relay's Noise link handshakes (see
//!   [`crate::transport`]) and is bound to the identity by the descriptor
//!   signature, so a peer that completes a Noise handshake with this key is
//!   the relay with this identity.

use std::fs::{DirBuilder, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use ed25519_dalek::{Signer, SigningKey};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::random_bytes;
use crate::identity::NodeId;

const IDENTITY_FILE: &str = "identity.key";

pub struct RelayKeys {
    identity: SigningKey,
    onion: StaticSecret,
    link: StaticSecret,
}

impl RelayKeys {
    /// Fresh identity and onion keys held only in memory.
    pub fn generate() -> Self {
        let seed = Zeroizing::new(random_bytes::<32>());
        Self {
            identity: SigningKey::from_bytes(&seed),
            onion: StaticSecret::from(random_bytes::<32>()),
            link: StaticSecret::from(random_bytes::<32>()),
        }
    }

    /// Load the identity key from `data_dir`, creating it on first run.
    /// A fresh onion key is generated either way.
    ///
    /// Refuses to use a key file readable by group or others.
    pub fn load_or_create(data_dir: &Path) -> io::Result<Self> {
        create_private_dir(data_dir, true)?;
        let path = data_dir.join(IDENTITY_FILE);
        let seed = match read_secret(&path) {
            Ok(seed) => seed,
            Err(e) if e.kind() == io::ErrorKind::NotFound => write_new_secret(&path)?,
            Err(e) => return Err(e),
        };

        Ok(Self {
            identity: SigningKey::from_bytes(&seed),
            onion: StaticSecret::from(random_bytes::<32>()),
            link: StaticSecret::from(random_bytes::<32>()),
        })
    }

    pub fn node_id(&self) -> NodeId {
        NodeId::from_bytes(self.identity.verifying_key().to_bytes())
    }

    pub fn onion_public(&self) -> [u8; 32] {
        PublicKey::from(&self.onion).to_bytes()
    }

    pub fn link_public(&self) -> [u8; 32] {
        PublicKey::from(&self.link).to_bytes()
    }

    /// The Noise link secret, for accepting links as this relay. Public so
    /// tests can run scripted hostile relays that speak real MORP.
    pub fn link_secret(&self) -> &StaticSecret {
        &self.link
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.identity.sign(message).to_bytes()
    }

    pub(crate) fn onion_secret(&self) -> &StaticSecret {
        &self.onion
    }
}

/// Where the identity key for `data_dir` is stored.
pub fn identity_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(IDENTITY_FILE)
}

// ------------------------------------------------- secret key files
// Shared by relay identity keys and service keys.

/// Create `dir` with mode 0700. With `allow_existing`, an existing directory
/// is accepted (its mode is left unchanged).
pub(crate) fn create_private_dir(dir: &Path, allow_existing: bool) -> io::Result<()> {
    if allow_existing {
        DirBuilder::new().recursive(true).mode(0o700).create(dir)
    } else {
        if let Some(parent) = dir.parent() {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
        }
        DirBuilder::new().mode(0o700).create(dir)
    }
}

/// Read a 32-byte secret, refusing files that group or others can access.
pub(crate) fn read_secret(path: &Path) -> io::Result<Zeroizing<[u8; 32]>> {
    let mut file = OpenOptions::new().read(true).open(path)?;
    let mode = file.metadata()?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is accessible by other users (mode {:o}); run: chmod 600 {}",
                path.display(),
                mode & 0o777,
                path.display()
            ),
        ));
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    let mut extra = [0u8; 1];
    file.read_exact(seed.as_mut())?;
    if file.read(&mut extra)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not a 32-byte key", path.display()),
        ));
    }
    Ok(seed)
}

/// Generate a random 32-byte secret and write it to a new file with mode
/// 0600. Fails if the file already exists.
pub(crate) fn write_new_secret(path: &Path) -> io::Result<Zeroizing<[u8; 32]>> {
    let seed = Zeroizing::new(random_bytes::<32>());
    write_secret(path, &seed)?;
    Ok(seed)
}

/// Write `secret` to a new file with mode 0600. Fails if the file exists.
pub(crate) fn write_secret(path: &Path, secret: &[u8; 32]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(secret)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn identity_persists_but_onion_key_rotates() {
        let dir = tempfile::tempdir().unwrap();
        let first = RelayKeys::load_or_create(dir.path()).unwrap();
        let second = RelayKeys::load_or_create(dir.path()).unwrap();
        assert_eq!(first.node_id(), second.node_id());
        assert_ne!(first.onion_public(), second.onion_public());
        assert_ne!(first.link_public(), second.link_public());
        assert_ne!(first.link_public(), first.onion_public());
    }

    #[test]
    fn key_file_is_private() {
        let dir = tempfile::tempdir().unwrap();
        RelayKeys::load_or_create(dir.path()).unwrap();
        let mode = fs::metadata(identity_path(dir.path()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn refuses_world_readable_key() {
        let dir = tempfile::tempdir().unwrap();
        RelayKeys::load_or_create(dir.path()).unwrap();
        let path = identity_path(dir.path());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let err = RelayKeys::load_or_create(dir.path()).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn refuses_truncated_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = identity_path(dir.path());
        fs::write(&path, [1u8; 10]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(RelayKeys::load_or_create(dir.path()).is_err());
    }

    #[test]
    fn generated_relays_are_distinct() {
        assert_ne!(
            RelayKeys::generate().node_id(),
            RelayKeys::generate().node_id()
        );
    }
}
