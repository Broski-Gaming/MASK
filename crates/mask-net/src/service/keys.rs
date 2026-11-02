//! Service identity keys.
//!
//! Each service has one Ed25519 key. Its public half *is* the `.morp`
//! address. The private key is stored at
//! `<services_dir>/<56-char id>/service.key` with mode 0600 inside a 0700
//! folder. The folder is named after the address so that no human-chosen
//! name exists anywhere; a mismatch between folder name and key is an error.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use zeroize::Zeroizing;

use crate::address::MorpAddress;
use crate::crypto::keys::{create_private_dir, read_secret, write_secret};
use crate::crypto::random_bytes;

const KEY_FILE: &str = "service.key";

pub struct ServiceKeys {
    signing: SigningKey,
    address: MorpAddress,
}

impl ServiceKeys {
    /// A fresh identity held only in memory.
    pub fn generate() -> Self {
        Self::generate_with_seed().0
    }

    fn generate_with_seed() -> (Self, Zeroizing<[u8; 32]>) {
        loop {
            let seed = Zeroizing::new(random_bytes::<32>());
            if let Ok(keys) = Self::from_seed(&seed) {
                return (keys, seed);
            }
        }
    }

    fn from_seed(seed: &[u8; 32]) -> io::Result<Self> {
        let signing = SigningKey::from_bytes(seed);
        let address = MorpAddress::from_public_key(signing.verifying_key().to_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(Self { signing, address })
    }

    /// Create a new identity under `services_dir`. Returns the keys and the
    /// service folder. Never overwrites an existing key.
    pub fn create_in(services_dir: &Path) -> io::Result<(Self, PathBuf)> {
        let (keys, seed) = Self::generate_with_seed();
        let dir = services_dir.join(keys.address.id());
        create_private_dir(&dir, false)?;
        write_secret(&dir.join(KEY_FILE), &seed)?;
        Ok((keys, dir))
    }

    /// Load the service in `service_dir`, checking that the folder name is
    /// the address of the key inside it.
    pub fn load(service_dir: &Path) -> io::Result<Self> {
        let seed = read_secret(&service_dir.join(KEY_FILE))?;
        let keys = Self::from_seed(&seed)?;
        let folder = service_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if folder != keys.address.id() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} holds the key for {}, not for a service named {folder:?}",
                    service_dir.display(),
                    keys.address
                ),
            ));
        }
        Ok(keys)
    }

    /// Load the service for `address` from `services_dir`.
    pub fn load_address(services_dir: &Path, address: &MorpAddress) -> io::Result<Self> {
        Self::load(&services_dir.join(address.id()))
    }

    /// Addresses of every service under `services_dir` whose key loads.
    pub fn list(services_dir: &Path) -> io::Result<Vec<Result<MorpAddress, String>>> {
        let mut out = Vec::new();
        let entries = match fs::read_dir(services_dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e),
        };
        for entry in entries {
            let path = entry?.path();
            if path.is_dir() {
                out.push(
                    Self::load(&path)
                        .map(|k| k.address)
                        .map_err(|e| format!("{}: {e}", path.display())),
                );
            }
        }
        Ok(out)
    }

    pub fn address(&self) -> &MorpAddress {
        &self.address
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }

    /// Where the private key for `address` would be stored.
    pub fn key_path(services_dir: &Path, address: &MorpAddress) -> PathBuf {
        services_dir.join(address.id()).join(KEY_FILE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn created_service_has_private_files_named_by_address() {
        let root = tempfile::tempdir().unwrap();
        let (keys, dir) = ServiceKeys::create_in(root.path()).unwrap();
        assert_eq!(
            dir.file_name().unwrap().to_str().unwrap(),
            keys.address().id()
        );

        let key_mode = fs::metadata(dir.join(KEY_FILE))
            .unwrap()
            .permissions()
            .mode();
        let dir_mode = fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(key_mode & 0o777, 0o600);
        assert_eq!(dir_mode & 0o777, 0o700);

        let loaded = ServiceKeys::load_address(root.path(), keys.address()).unwrap();
        assert_eq!(loaded.address(), keys.address());
    }

    #[test]
    fn each_new_service_gets_a_new_address() {
        let root = tempfile::tempdir().unwrap();
        let (a, _) = ServiceKeys::create_in(root.path()).unwrap();
        let (b, _) = ServiceKeys::create_in(root.path()).unwrap();
        assert_ne!(a.address(), b.address());
        let listed: Vec<_> = ServiceKeys::list(root.path())
            .unwrap()
            .into_iter()
            .map(Result::unwrap)
            .collect();
        assert_eq!(listed.len(), 2);
    }

    #[test]
    fn renamed_folder_cannot_claim_another_address() {
        let root = tempfile::tempdir().unwrap();
        let (a, dir_a) = ServiceKeys::create_in(root.path()).unwrap();
        let other = ServiceKeys::generate();
        let fake_dir = root.path().join(other.address().id());
        fs::rename(&dir_a, &fake_dir).unwrap();
        assert!(ServiceKeys::load(&fake_dir).is_err());
        assert!(ServiceKeys::load_address(root.path(), a.address()).is_err());
    }

    #[test]
    fn refuses_readable_key_file() {
        let root = tempfile::tempdir().unwrap();
        let (keys, dir) = ServiceKeys::create_in(root.path()).unwrap();
        fs::set_permissions(dir.join(KEY_FILE), fs::Permissions::from_mode(0o640)).unwrap();
        let err = ServiceKeys::load_address(root.path(), keys.address())
            .err()
            .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }
}
