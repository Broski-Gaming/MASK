//! MORP services: sites identified only by a cryptographic `.morp` address.
//!
//! **v0.4 prototype — location is NOT hidden.** A service's descriptor
//! contains its real loopback address, and clients connect to it directly.
//! The connection is authenticated (the service proves it holds the
//! address's private key) and encrypted, but the relays are not used yet.
//! Introduction points and rendezvous circuits are planned for v0.5.
//!
//! - [`keys`]: service identity keys and their storage.
//! - [`descriptor`]: signed, expiring service descriptors and withdrawals.
//! - [`channel`]: authenticated, encrypted client ↔ service connection.
//! - [`site`]: safe static-file serving from a site folder.
//! - [`host`]: the service host (listener + site).
//! - [`fetch`]: resolve an address through the directory and fetch a page.

pub mod channel;
pub mod descriptor;
pub mod fetch;
pub mod host;
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
