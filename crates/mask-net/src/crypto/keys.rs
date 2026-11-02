//! Relay key material.
//!
//! - **Identity key** (Ed25519): long-term, stored in `<data_dir>/identity.key`
//!   with mode 0600. Its public half is the relay's [`NodeId`].
//! - **Onion key** (X25519): generated fresh every time the relay starts and
//!   never written to disk. It is bound to the identity by the signed relay
//!   descriptor. Restarting a relay therefore invalidates old descriptors.

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
}

impl RelayKeys {
    /// Fresh identity and onion keys held only in memory.
    pub fn generate() -> Self {
        let seed = Zeroizing::new(random_bytes::<32>());
        Self {
            identity: SigningKey::from_bytes(&seed),
            onion: StaticSecret::from(random_bytes::<32>()),
        }
    }

    /// Load the identity key from `data_dir`, creating it on first run.
    /// A fresh onion key is generated either way.
    ///
    /// Refuses to use a key file readable by group or others.
    pub fn load_or_create(data_dir: &Path) -> io::Result<Self> {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(data_dir)?;
        let path = data_dir.join(IDENTITY_FILE);

        let seed = match OpenOptions::new().read(true).open(&path) {
            Ok(mut file) => {
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
                seed
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let seed = Zeroizing::new(random_bytes::<32>());
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)?;
                file.write_all(seed.as_ref())?;
                file.sync_all()?;
                seed
            }
            Err(e) => return Err(e),
        };

        Ok(Self {
            identity: SigningKey::from_bytes(&seed),
            onion: StaticSecret::from(random_bytes::<32>()),
        })
    }

    pub fn node_id(&self) -> NodeId {
        NodeId::from_bytes(self.identity.verifying_key().to_bytes())
    }

    pub fn onion_public(&self) -> [u8; 32] {
        PublicKey::from(&self.onion).to_bytes()
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
