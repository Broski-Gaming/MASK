//! MORP services: sites identified only by a cryptographic `.morp` address.
//!
//! - [`keys`]: service identity keys and their storage.
//! - [`descriptor`]: signed, expiring service descriptors (introduction
//!   points only, no location) and withdrawals.
//! - [`site`]: safe static-file serving from a site folder.
//!
//! Hosting and connecting happen through relay circuits; see
//! [`crate::hs`].

pub mod descriptor;
pub mod keys;
pub mod site;

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Milliseconds since the Unix epoch, used as a descriptor revision.
pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
